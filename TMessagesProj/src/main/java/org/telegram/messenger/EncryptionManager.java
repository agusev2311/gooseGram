package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.Base64;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.telegram.tgnet.TLRPC;


import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionManager {
    public static final String ENCRYPTION_PREFIX = "[ENCRYPTED] ";
    public static final String ENCRYPTED_TEXT_DOCUMENT_MIME = "application/x-goosegram-encrypted-text";
    public static final String KEY_TRANSFER_DOCUMENT_MIME = "application/x-goosegram-key-transfer";
    public static final String PARAM_UPLOAD_PATH = "enc_upload_path";
    public static final String PARAM_PREVIEW_TEXT = "enc_preview_text";
    public static final String PARAM_SKIP_AUTO_ENCRYPTION = "enc_skip_auto";
    public static final String ENCRYPTED_IMAGE_NAME_PREFIX = "ggenc_photo_";

    private static final String PREF_CONFIG = "encryption_config";
    private static final String PREF_KEYS = "encryption_keys";
    private static final String PREF_CACHE = "encryption_cache";
    private static final String PREF_MESSAGE_BUBBLE_COLOR = "message_bubble_color";
    private static final int AES_KEY_SIZE_BYTES = 32;
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int NETWORK_TIMEOUT_MS = 10000;
    private static final int TELEGRAM_TEXT_LIMIT = 4096;
    private static final int FILE_BUFFER_SIZE = 32 * 1024;
    private static final int FILE_HEADER_LIMIT = 32 * 1024;
    private static final byte[] ENCRYPTED_FILE_MAGIC = new byte[]{'G', 'G', 'E', '1'};
    private static final String KEY_TRANSFER_MAGIC = "GGKT1";
    private static final String KEY_TRANSFER_ACK_PREFIX = "[GG_KEY_TRANSFER_ACK]";
    private static final String KEY_TRANSFER_FILE_EXTENSION = ".ggkey";
    private static final String KEY_TRANSFER_FILE_PREFIX = "gg_key_transfer_";
    private static final int KEY_TRANSFER_SALT_BYTES = 16;
    private static final int KEY_TRANSFER_PBKDF2_ITERATIONS = 150000;
    private static final int KEY_TRANSFER_PASSWORD_GROUPS = 4;
    private static final int KEY_TRANSFER_PASSWORD_GROUP_SIZE = 5;
    private static final String KEY_TRANSFER_PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    private static final Map<String, String> publicKeyCache = new ConcurrentHashMap<>();

    public interface SimpleCallback<T> {
        void onResult(T result, String error);
    }

    public static class DisplayResult {
        public final String displayText;
        public final String statusLine;
        public final boolean encrypted;
        public final boolean error;

        public DisplayResult(String displayText, String statusLine, boolean encrypted, boolean error) {
            this.displayText = displayText;
            this.statusLine = statusLine;
            this.encrypted = encrypted;
            this.error = error;
        }
    }

    private static SharedPreferences getPrefs(String name) {
        return ApplicationLoader.applicationContext.getSharedPreferences(name, Context.MODE_PRIVATE);
    }

    private static String keyForAccount(String key, int account) {
        return key + "_" + account;
    }

    public static boolean isRegistered(int account) {
        return getPrefs(PREF_CONFIG).getBoolean(keyForAccount("registered", account), false);
    }

    public static boolean isVerified(int account) {
        return getPrefs(PREF_CONFIG).getBoolean(keyForAccount("verified", account), false);
    }

    public static String getServerAddress(int account) {
        return getPrefs(PREF_CONFIG).getString(keyForAccount("server", account), "");
    }

    public static void setServerAddress(int account, String address) {
        String normalized = normalizeServerAddress(address);
        String key = keyForAccount("server", account);
        String current = getPrefs(PREF_CONFIG).getString(key, "");
        if (!TextUtils.equals(current, normalized)) {
            getPrefs(PREF_CONFIG).edit().putString(key, normalized).apply();
            clearCache(account);
        }
    }

    public static class OutgoingTextResult {
        public final String encryptedText;
        public final File previewFile;
        public final File uploadFile;

        public OutgoingTextResult(String encryptedText, File previewFile, File uploadFile) {
            this.encryptedText = encryptedText;
            this.previewFile = previewFile;
            this.uploadFile = uploadFile;
        }
    }

    public static class KeyTransferExportResult {
        public final String password;
        public final String transferId;

        public KeyTransferExportResult(String password, String transferId) {
            this.password = password;
            this.transferId = transferId;
        }
    }

    public static int getCustomMessageBubbleColor(int account) {
        return getPrefs(PREF_CONFIG).getInt(keyForAccount(PREF_MESSAGE_BUBBLE_COLOR, account), 0);
    }

    public static void setCustomMessageBubbleColor(int account, int color) {
        getPrefs(PREF_CONFIG).edit().putInt(keyForAccount(PREF_MESSAGE_BUBBLE_COLOR, account), color).apply();
    }

    private static String dialogEncryptionKey(int account, long dialogId) {
        return keyForAccount("dialog_encryption_enabled_" + dialogId, account);
    }

    public static boolean canUseEncryptionInDialog(int account, long dialogId) {
        if (dialogId == 0 || DialogObject.isEncryptedDialog(dialogId) || !DialogObject.isUserDialog(dialogId)) {
            return false;
        }
        long selfUserId = UserConfig.getInstance(account).getClientUserId();
        if (selfUserId != 0 && dialogId == selfUserId) {
            return false;
        }
        TLRPC.User user = MessagesController.getInstance(account).getUser(dialogId);
        return user == null || !user.bot;
    }

    public static boolean isEncryptionEnabledForDialog(int account, long dialogId) {
        return canUseEncryptionInDialog(account, dialogId)
                && getPrefs(PREF_CONFIG).getBoolean(dialogEncryptionKey(account, dialogId), true);
    }

    public static void setEncryptionEnabledForDialog(int account, long dialogId, boolean enabled) {
        SharedPreferences.Editor editor = getPrefs(PREF_CONFIG).edit();
        if (!canUseEncryptionInDialog(account, dialogId)) {
            editor.remove(dialogEncryptionKey(account, dialogId)).apply();
            return;
        }
        editor.putBoolean(dialogEncryptionKey(account, dialogId), enabled).apply();
    }

    public static void sendKeyTransferToSavedMessages(int account, SimpleCallback<KeyTransferExportResult> callback) {
        Utilities.globalQueue.postRunnable(() -> {
            try {
                long selfId = UserConfig.getInstance(account).getClientUserId();
                if (selfId == 0) {
                    postResult(callback, null, LocaleController.getString(R.string.EncryptionKeyTransferWrongAccount));
                    return;
                }
                KeyBundle keys = ensureKeys(account);
                String password = generateKeyTransferPassword();
                String normalizedPassword = normalizeKeyTransferPassword(password);
                String transferId = generateTransferId();

                JSONObject payload = new JSONObject();
                payload.put("magic", KEY_TRANSFER_MAGIC);
                payload.put("v", 1);
                payload.put("transfer_id", transferId);
                payload.put("user_id", selfId);
                payload.put("server", getServerAddress(account));
                payload.put("registered", isRegistered(account));
                payload.put("verified", isVerified(account));
                payload.put("rsa_public", keys.rsaPublicB64);
                payload.put("rsa_private", getPrefs(PREF_KEYS).getString(keyForAccount("rsa_private", account), ""));
                payload.put("created_at", System.currentTimeMillis());
                String payloadJson = payload.toString(2);

                byte[] salt = new byte[KEY_TRANSFER_SALT_BYTES];
                byte[] iv = new byte[GCM_IV_BYTES];
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(salt);
                secureRandom.nextBytes(iv);
                byte[] encrypted = encryptWithPassword(normalizedPassword, payloadJson.getBytes(StandardCharsets.UTF_8), salt, iv);

                JSONObject filePayload = new JSONObject();
                filePayload.put("magic", KEY_TRANSFER_MAGIC);
                filePayload.put("v", 1);
                filePayload.put("transfer_id", transferId);
                filePayload.put("salt", bytesToJsonArray(salt));
                filePayload.put("iv", bytesToJsonArray(iv));
                filePayload.put("ciphertext", bytesToJsonArray(encrypted));

                File transferFile = createTempKeyTransferFile(transferId);
                try (FileOutputStream outputStream = new FileOutputStream(transferFile)) {
                    outputStream.write(filePayload.toString(2).getBytes(StandardCharsets.UTF_8));
                }

                AndroidUtilities.runOnUIThread(() -> {
                    ArrayList<String> files = new ArrayList<>();
                    files.add(transferFile.getAbsolutePath());
                    SendMessagesHelper.prepareSendingDocuments(
                            AccountInstance.getInstance(account),
                            files,
                            files,
                            null,
                            LocaleController.getString(R.string.EncryptionKeyTransferDocumentCaption),
                            null,
                            selfId,
                            null,
                            null,
                            null,
                            null,
                            null,
                            false,
                            0,
                            null,
                            null,
                            0,
                            0,
                            false,
                            0
                    );
                    callback.onResult(new KeyTransferExportResult(password, transferId), null);
                });
            } catch (Exception e) {
                postResult(callback, null, LocaleController.getString(R.string.EncryptionKeyTransferExportFailed));
            }
        });
    }

    public static void importKeyTransferFile(int account, TLRPC.Message message, File file, String password, SimpleCallback<String> callback) {
        Utilities.globalQueue.postRunnable(() -> {
            if (file == null || !file.exists()) {
                postResult(callback, null, LocaleController.getString(R.string.EncryptionKeyTransferDownloadFirst));
                return;
            }
            if (message != null && !isKeyTransferMessage(message)) {
                postResult(callback, null, LocaleController.getString(R.string.EncryptionKeyTransferInvalidFile));
                return;
            }
            try {
                JSONObject wrapper = new JSONObject(readUtf8File(file));
                if (!TextUtils.equals(KEY_TRANSFER_MAGIC, wrapper.optString("magic"))) {
                    postResult(callback, null, LocaleController.getString(R.string.EncryptionKeyTransferInvalidFile));
                    return;
                }

                byte[] salt = parseBinaryField(wrapper, "salt");
                byte[] iv = parseBinaryField(wrapper, "iv");
                byte[] cipherText = parseBinaryField(wrapper, "ciphertext");
                byte[] plain = decryptWithPassword(normalizeKeyTransferPassword(password), cipherText, salt, iv);
                JSONObject payload = new JSONObject(new String(plain, StandardCharsets.UTF_8));
                if (!TextUtils.equals(KEY_TRANSFER_MAGIC, payload.optString("magic"))) {
                    postResult(callback, null, LocaleController.getString(R.string.EncryptionKeyTransferInvalidFile));
                    return;
                }

                long currentUserId = UserConfig.getInstance(account).getClientUserId();
                long payloadUserId = payload.optLong("user_id", 0);
                if (currentUserId == 0 || payloadUserId == 0 || currentUserId != payloadUserId) {
                    postResult(callback, null, LocaleController.getString(R.string.EncryptionKeyTransferWrongAccount));
                    return;
                }

                String publicKey = payload.optString("rsa_public", "");
                String privateKey = payload.optString("rsa_private", "");
                if (TextUtils.isEmpty(publicKey) || TextUtils.isEmpty(privateKey)) {
                    postResult(callback, null, LocaleController.getString(R.string.EncryptionKeyTransferInvalidFile));
                    return;
                }
                validateImportedKeyPair(publicKey, privateKey);

                SharedPreferences.Editor keysEditor = getPrefs(PREF_KEYS).edit();
                keysEditor.putString(keyForAccount("rsa_public", account), publicKey);
                keysEditor.putString(keyForAccount("rsa_private", account), privateKey);
                keysEditor.apply();

                SharedPreferences.Editor configEditor = getPrefs(PREF_CONFIG).edit();
                configEditor.putString(keyForAccount("server", account), normalizeServerAddress(payload.optString("server", "")));
                configEditor.putBoolean(keyForAccount("registered", account), payload.optBoolean("registered", false));
                configEditor.putBoolean(keyForAccount("verified", account), payload.optBoolean("verified", false));
                configEditor.apply();
                clearCache(account);

                if (file.exists()) {
                    file.delete();
                }

                String transferId = payload.optString("transfer_id", wrapper.optString("transfer_id", ""));
                if (!TextUtils.isEmpty(transferId)) {
                    sendKeyTransferAck(account, transferId);
                }
                postResult(callback, LocaleController.getString(R.string.EncryptionKeyTransferImportSuccess), null);
            } catch (Exception e) {
                postResult(callback, null, LocaleController.getString(R.string.EncryptionKeyTransferInvalidPassword));
            }
        });
    }

    public static boolean isKeyTransferMessage(TLRPC.Message message) {
        if (message == null || !(MessageObject.getMedia(message) instanceof TLRPC.TL_messageMediaDocument)) {
            return false;
        }
        return isKeyTransferDocument(MessageObject.getMedia(message).document);
    }

    public static boolean isKeyTransferDocument(TLRPC.Document document) {
        if (document == null) {
            return false;
        }
        if (TextUtils.equals(document.mime_type, KEY_TRANSFER_DOCUMENT_MIME)) {
            return true;
        }
        return isKeyTransferFileName(FileLoader.getDocumentFileName(document));
    }

    public static boolean isKeyTransferFileName(String fileName) {
        return !TextUtils.isEmpty(fileName) && fileName.toLowerCase().endsWith(KEY_TRANSFER_FILE_EXTENSION);
    }

    public static boolean shouldSkipAutoEncryption(Map<String, String> params, TLRPC.Document document, String path) {
        if (params != null && "1".equals(params.get(PARAM_SKIP_AUTO_ENCRYPTION))) {
            return true;
        }
        if (isKeyTransferDocument(document)) {
            return true;
        }
        return isKeyTransferFileName(path);
    }

    public static String getKeyTransferAckText(TLRPC.Message message) {
        if (message == null || TextUtils.isEmpty(message.message) || !message.message.startsWith(KEY_TRANSFER_ACK_PREFIX)) {
            return null;
        }
        return LocaleController.getString(R.string.EncryptionKeyTransferAckMessage);
    }

    public static void clearCache(int account) {
        String cacheKey = keyForAccount("public_keys", account);
        getPrefs(PREF_CACHE).edit().remove(cacheKey).apply();
        publicKeyCache.clear();
    }

    public static void registerUser(int account, SimpleCallback<String> callback) {
        Utilities.globalQueue.postRunnable(() -> {
            String server = getServerAddress(account);
            if (TextUtils.isEmpty(server)) {
                respond(callback, null, "Server address is empty");
                return;
            }
            long userId = UserConfig.getInstance(account).getClientUserId();
            try {
                try {
                    ensureKeys(account);
                } catch (Exception e) {
                    respond(callback, null, "Key generation failed: " + safeError(e));
                    return;
                }
                JSONObject payload = new JSONObject();
                payload.put("userid", userId);
                String url = server + "/api/v1/register";
                JSONObject response = postJson(url, payload);
                if (response == null) {
                    respond(callback, null, "Empty response");
                    return;
                }
                String status = response.optString("status", null);
                if (!TextUtils.isEmpty(status) || responseIndicatesSuccess(response, "registered")) {
                    getPrefs(PREF_CONFIG).edit()
                        .putBoolean(keyForAccount("registered", account), true)
                        .apply();
                    respond(callback, !TextUtils.isEmpty(status) ? status : LocaleController.getString(R.string.EncryptionStatusRegistered), null);
                } else {
                    respond(callback, null, response.optString("error", "Unknown error"));
                }
            } catch (Exception e) {
                respond(callback, null, "Register failed: " + safeError(e));
            }
        });
    }

    public static void verifyUser(int account, String verifySecret, SimpleCallback<String> callback) {
        Utilities.globalQueue.postRunnable(() -> {
            String server = getServerAddress(account);
            if (TextUtils.isEmpty(server)) {
                respond(callback, null, "Server address is empty");
                return;
            }
            if (TextUtils.isEmpty(verifySecret)) {
                respond(callback, null, "Verify secret is empty");
                return;
            }
            long userId = UserConfig.getInstance(account).getClientUserId();
            try {
                KeyBundle keys;
                try {
                    keys = ensureKeys(account);
                } catch (Exception e) {
                    respond(callback, null, "Key generation failed: " + safeError(e));
                    return;
                }
                JSONObject publicKey = new JSONObject();
                publicKey.put("v", 1);
                publicKey.put("rsa", keys.rsaPublicB64);
                JSONObject payload = new JSONObject();
                payload.put("userid", userId);
                payload.put("public_key", publicKey.toString());
                payload.put("verify_secret", verifySecret);

                String url = server + "/api/v1/verify";
                JSONObject response = postJson(url, payload);
                if (response == null) {
                    respond(callback, null, "Empty response");
                    return;
                }
                String status = response.optString("status", null);
                if (!TextUtils.isEmpty(status) || responseIndicatesSuccess(response, "verified")) {
                    getPrefs(PREF_CONFIG).edit()
                        .putBoolean(keyForAccount("verified", account), true)
                        .apply();
                    respond(callback, !TextUtils.isEmpty(status) ? status : LocaleController.getString(R.string.EncryptionStatusVerified), null);
                } else {
                    respond(callback, null, response.optString("error", "Unknown error"));
                }
            } catch (Exception e) {
                respond(callback, null, "Verify failed: " + safeError(e));
            }
        });
    }

    public static void encryptOutgoingText(int account, long peerUserId, String message, SimpleCallback<String> callback) {
        Utilities.globalQueue.postRunnable(() -> {
            if (TextUtils.isEmpty(message)) {
                respond(callback, null, "Message is empty");
                return;
            }
            if (message.startsWith(ENCRYPTION_PREFIX)) {
                respond(callback, message, null);
                return;
            }
            try {
                String encrypted = encryptOutgoingTextBlocking(account, peerUserId, message);
                respond(callback, encrypted, null);
            } catch (Exception e) {
                respond(callback, null, e.getMessage());
            }
        });
    }

    public static void encryptOutgoingTextOrFile(int account, long peerUserId, String message, SimpleCallback<OutgoingTextResult> callback) {
        Utilities.globalQueue.postRunnable(() -> {
            if (TextUtils.isEmpty(message)) {
                respond(callback, null, "Message is empty");
                return;
            }
            try {
                String encrypted = encryptOutgoingTextBlocking(account, peerUserId, message);
                if (encrypted.length() <= TELEGRAM_TEXT_LIMIT) {
                    respond(callback, new OutgoingTextResult(encrypted, null, null), null);
                    return;
                }
                File previewFile = createTempTextFile("enc_preview_", message);
                File uploadFile = createTempTextFile("enc_upload_", encrypted);
                respond(callback, new OutgoingTextResult(null, previewFile, uploadFile), null);
            } catch (Exception e) {
                respond(callback, null, e.getMessage());
            }
        });
    }

    public static File encryptOutgoingMediaFile(int account, long peerUserId, File sourceFile) throws Exception {
        if (sourceFile == null || !sourceFile.exists() || sourceFile.length() == 0) {
            throw new IOException("File is empty");
        }
        OutgoingPeerContext context = buildOutgoingPeerContext(account, peerUserId);
        return encryptBinaryFile(sourceFile, context);
    }

    public static String getOutgoingEncryptionError(int account, long peerUserId) {
        try {
            buildOutgoingPeerContext(account, peerUserId);
            return null;
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    public static DisplayResult getDisplayText(int account, long senderUserId, String originalText) {
        if (TextUtils.isEmpty(originalText)) {
            return new DisplayResult("", LocaleController.getString(R.string.EncryptionMessageNotEncrypted), false, false);
        }
        if (originalText.startsWith(KEY_TRANSFER_ACK_PREFIX)) {
            return new DisplayResult(LocaleController.getString(R.string.EncryptionKeyTransferAckMessage), null, false, false);
        }
        if (!originalText.startsWith(ENCRYPTION_PREFIX)) {
            return new DisplayResult(originalText, LocaleController.getString(R.string.EncryptionMessageNotEncrypted), false, false);
        }
        try {
            KeyBundle keys = ensureKeys(account);
            String payloadB64 = originalText.substring(ENCRYPTION_PREFIX.length());
            JSONObject payload;
            try {
                String decoded = new String(Base64.decode(payloadB64, Base64.NO_WRAP), StandardCharsets.UTF_8);
                payload = new JSONObject(decoded);
            } catch (Exception e) {
                return new DisplayResult(originalText, LocaleController.getString(R.string.EncryptionMessageInvalidPayload), true, true);
            }
            String ivB64 = payload.getString("iv");
            String cipherB64 = payload.getString("ciphertext");
            String keyToB64 = payload.getString("key_to");
            String keyFromB64 = payload.getString("key_from");
            long sender = payload.optLong("sender", senderUserId);

            byte[] aesKey = tryDecryptAesKey(keys, keyToB64, keyFromB64);
            if (aesKey == null) {
                return new DisplayResult(originalText, LocaleController.getString(R.string.EncryptionMessageKeyDecryptError), true, true);
            }
            String decrypted;
            try {
                decrypted = decryptAes(aesKey, ivB64, cipherB64);
            } catch (GeneralSecurityException e) {
                return new DisplayResult(originalText, LocaleController.getString(R.string.EncryptionMessageDecryptError), true, true);
            }
            String status = LocaleController.getString(R.string.EncryptionMessageDecrypted);
            return new DisplayResult(decrypted, status, true, false);
        } catch (Exception e) {
            return new DisplayResult(originalText, LocaleController.getString(R.string.EncryptionMessageDecryptError), true, true);
        }
    }

    public static DisplayResult getDisplayText(int account, TLRPC.Message message, long senderUserId) {
        if (message == null) {
            return new DisplayResult("", LocaleController.getString(R.string.EncryptionMessageNotEncrypted), false, false);
        }
        if (isEncryptedTextDocument(message)) {
            return getDisplayTextFromEncryptedDocument(account, message, senderUserId);
        }
        return getDisplayText(account, senderUserId, message.message);
    }

    public static boolean isEncryptedMessage(TLRPC.Message message) {
        return message != null && (isEncryptedTextDocument(message)
                || !TextUtils.isEmpty(message.message) && message.message.startsWith(ENCRYPTION_PREFIX));
    }

    public static boolean isEncryptedTextDocument(TLRPC.Message message) {
        return message != null
                && MessageObject.getMedia(message) instanceof TLRPC.TL_messageMediaDocument
                && MessageObject.getMedia(message).document != null
                && TextUtils.equals(MessageObject.getMedia(message).document.mime_type, ENCRYPTED_TEXT_DOCUMENT_MIME);
    }

    public static boolean isEncryptedImageDocument(TLRPC.Message message) {
        return message != null
                && MessageObject.getMedia(message) instanceof TLRPC.TL_messageMediaDocument
                && isEncryptedImageDocument(MessageObject.getMedia(message).document);
    }

    public static void markEncryptedImageDocument(TLRPC.Document document) {
        if (!isPreviewableImageDocument(document)) {
            return;
        }
        TLRPC.TL_documentAttributeFilename fileNameAttribute = null;
        for (int i = 0; i < document.attributes.size(); i++) {
            TLRPC.DocumentAttribute attribute = document.attributes.get(i);
            if (attribute instanceof TLRPC.TL_documentAttributeFilename) {
                fileNameAttribute = (TLRPC.TL_documentAttributeFilename) attribute;
                break;
            }
        }
        if (fileNameAttribute == null) {
            fileNameAttribute = new TLRPC.TL_documentAttributeFilename();
            fileNameAttribute.file_name = ENCRYPTED_IMAGE_NAME_PREFIX + "image";
            document.attributes.add(0, fileNameAttribute);
            return;
        }
        if (TextUtils.isEmpty(fileNameAttribute.file_name)) {
            fileNameAttribute.file_name = ENCRYPTED_IMAGE_NAME_PREFIX + "image";
        } else if (!fileNameAttribute.file_name.startsWith(ENCRYPTED_IMAGE_NAME_PREFIX)) {
            fileNameAttribute.file_name = ENCRYPTED_IMAGE_NAME_PREFIX + fileNameAttribute.file_name;
        }
    }

    public static File ensureDecryptedMediaFile(int account, TLRPC.Message message, File file) {
        if (file == null || !file.exists() || isEncryptedTextDocument(message)) {
            return file;
        }
        EncryptedFileHeader header;
        try {
            header = readEncryptedFileHeader(file);
        } catch (Exception e) {
            return file;
        }
        if (header == null) {
            return file;
        }
        File tempFile = null;
        try {
            KeyBundle keys = ensureKeys(account);
            byte[] aesKey = tryDecryptAesKey(keys, header.keyTo, header.keyFrom);
            if (aesKey == null) {
                return file;
            }
            tempFile = new File(file.getParentFile(), file.getName() + ".dec");
            decryptBinaryFile(file, tempFile, header, aesKey);
            replaceFile(tempFile, file);
        } catch (Exception e) {
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
        }
        return file;
    }

    public static String getWarningTextForError(String error) {
        if (TextUtils.isEmpty(error)) {
            return LocaleController.getString(R.string.EncryptionFailedGeneric);
        }
        if (error.contains("Server address is empty")) {
            return LocaleController.getString(R.string.EncryptionServerNotConfigured);
        }
        if (error.contains("User is not verified")) {
            return LocaleController.getString(R.string.EncryptionSelfNotVerified);
        }
        if (error.contains("User not registered")) {
            return LocaleController.getString(R.string.EncryptionRecipientUnavailable);
        }
        return LocaleController.getString(R.string.EncryptionFailedGeneric);
    }

    private static String normalizeServerAddress(String address) {
        if (TextUtils.isEmpty(address)) {
            return "";
        }
        String normalized = address.trim();
        if (!normalized.startsWith("http://") && !normalized.startsWith("https://")) {
            normalized = "http://" + normalized;
        }
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private static boolean isEncryptedImageDocument(TLRPC.Document document) {
        if (!isPreviewableImageDocument(document)) {
            return false;
        }
        String fileName = FileLoader.getDocumentFileName(document);
        return !TextUtils.isEmpty(fileName) && fileName.startsWith(ENCRYPTED_IMAGE_NAME_PREFIX);
    }

    private static boolean isPreviewableImageDocument(TLRPC.Document document) {
        if (document == null || TextUtils.isEmpty(document.mime_type)) {
            return false;
        }
        String mimeType = document.mime_type.toLowerCase();
        return mimeType.startsWith("image/")
                && !"image/gif".equals(mimeType)
                && !"image/webp".equals(mimeType)
                && MessageObject.canPreviewDocument(document);
    }

    private static <T> void respond(SimpleCallback<T> callback, T result, String error) {
        AndroidUtilities.runOnUIThread(() -> {
            if (!TextUtils.isEmpty(error)) {
                showEncryptionWarning(error);
            }
            callback.onResult(result, error);
        });
    }

    private static <T> void postResult(SimpleCallback<T> callback, T result, String error) {
        AndroidUtilities.runOnUIThread(() -> callback.onResult(result, error));
    }

    private static boolean responseIndicatesSuccess(JSONObject response, String keyword) {
        if (response == null) {
            return false;
        }
        String raw = response.optString("raw", "");
        String error = response.optString("error", "");
        String text = (raw + " " + error).toLowerCase();
        return text.contains(keyword);
    }

    private static String safeError(Throwable e) {
        if (e == null) {
            return "Unknown error";
        }
        String message = e.getMessage();
        if (TextUtils.isEmpty(message)) {
            return e.getClass().getSimpleName();
        }
        return e.getClass().getSimpleName() + ": " + message;
    }

    private static String encryptOutgoingTextBlocking(int account, long peerUserId, String message) throws Exception {
        if (message.startsWith(ENCRYPTION_PREFIX)) {
            return message;
        }
        OutgoingPeerContext context = buildOutgoingPeerContext(account, peerUserId);
        return encryptPayload(context.keys, context.peerKey, message, context.senderUserId);
    }

    private static OutgoingPeerContext buildOutgoingPeerContext(int account, long peerUserId) throws Exception {
        if (!DialogObject.isUserDialog(peerUserId)) {
            throw new GeneralSecurityException("Peer is not a user dialog");
        }
        String server = getServerAddress(account);
        if (TextUtils.isEmpty(server)) {
            throw new IOException("Server address is empty");
        }
        if (!isVerified(account)) {
            throw new GeneralSecurityException("User is not verified");
        }
        KeyBundle keys = ensureKeys(account);
        PublicKeyInfo peerKey = getPublicKey(account, peerUserId);
        if (peerKey == null) {
            throw new GeneralSecurityException("User not registered or not verified");
        }
        return new OutgoingPeerContext(keys, peerKey, UserConfig.getInstance(account).getClientUserId());
    }

    private static KeyBundle ensureKeys(int account) throws GeneralSecurityException {
        SharedPreferences prefs = getPrefs(PREF_KEYS);
        String rsaPublicKey = prefs.getString(keyForAccount("rsa_public", account), null);
        String rsaPrivateKey = prefs.getString(keyForAccount("rsa_private", account), null);
        if (rsaPublicKey == null || rsaPrivateKey == null) {
            KeyPair rsaPair;
            try {
                KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
                rsaGen.initialize(2048);
                rsaPair = rsaGen.generateKeyPair();
            } catch (Exception e) {
                throw new GeneralSecurityException("RSA key generation failed: " + safeError(e), e);
            }

            rsaPublicKey = Base64.encodeToString(rsaPair.getPublic().getEncoded(), Base64.NO_WRAP);
            rsaPrivateKey = Base64.encodeToString(rsaPair.getPrivate().getEncoded(), Base64.NO_WRAP);

            prefs.edit()
                .putString(keyForAccount("rsa_public", account), rsaPublicKey)
                .putString(keyForAccount("rsa_private", account), rsaPrivateKey)
                .apply();
        }

        PublicKey rsaPublic = decodePublicKey("RSA", rsaPublicKey);
        PrivateKey rsaPrivate = decodePrivateKey("RSA", rsaPrivateKey);
        return new KeyBundle(rsaPublic, rsaPrivate, rsaPublicKey);
    }

    private static PublicKey decodePublicKey(String algorithm, String b64) throws GeneralSecurityException {
        byte[] data = Base64.decode(b64, Base64.NO_WRAP);
        return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(data));
    }

    private static PrivateKey decodePrivateKey(String algorithm, String b64) throws GeneralSecurityException {
        byte[] data = Base64.decode(b64, Base64.NO_WRAP);
        return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(data));
    }

    private static String encryptPayload(KeyBundle keys, PublicKeyInfo peerKey, String message, long senderUserId) throws GeneralSecurityException, JSONException {
        byte[] aesKey = new byte[AES_KEY_SIZE_BYTES];
        new SecureRandom().nextBytes(aesKey);

        byte[] iv = new byte[GCM_IV_BYTES];
        new SecureRandom().nextBytes(iv);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] cipherText = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));

        String keyToB64 = Base64.encodeToString(rsaEncrypt(aesKey, peerKey.rsaPublic), Base64.NO_WRAP);
        String keyFromB64 = Base64.encodeToString(rsaEncrypt(aesKey, keys.rsaPublic), Base64.NO_WRAP);

        JSONObject payload = new JSONObject();
        payload.put("v", 1);
        payload.put("sender", senderUserId);
        payload.put("iv", Base64.encodeToString(iv, Base64.NO_WRAP));
        payload.put("ciphertext", Base64.encodeToString(cipherText, Base64.NO_WRAP));
        payload.put("key_to", keyToB64);
        payload.put("key_from", keyFromB64);

        String encoded = Base64.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
        return ENCRYPTION_PREFIX + encoded;
    }

    private static byte[] rsaEncrypt(byte[] data, PublicKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static byte[] tryDecryptAesKey(KeyBundle keys, String keyToB64, String keyFromB64) throws GeneralSecurityException {
        byte[] keyTo = Base64.decode(keyToB64, Base64.NO_WRAP);
        byte[] keyFrom = Base64.decode(keyFromB64, Base64.NO_WRAP);
        return tryDecryptAesKey(keys, keyTo, keyFrom);
    }

    private static byte[] tryDecryptAesKey(KeyBundle keys, byte[] keyTo, byte[] keyFrom) throws GeneralSecurityException {
        byte[] result = rsaDecryptOrNull(keyTo, keys.rsaPrivate);
        if (result != null) {
            return result;
        }
        return rsaDecryptOrNull(keyFrom, keys.rsaPrivate);
    }

    private static byte[] rsaDecryptOrNull(byte[] data, PrivateKey key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    private static String decryptAes(byte[] aesKey, String ivB64, String cipherB64) throws GeneralSecurityException {
        byte[] iv = Base64.decode(ivB64, Base64.NO_WRAP);
        byte[] cipherText = Base64.decode(cipherB64, Base64.NO_WRAP);
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] plain = aes.doFinal(cipherText);
        return new String(plain, StandardCharsets.UTF_8);
    }

    private static byte[] encryptWithPassword(String password, byte[] plain, byte[] salt, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derivePasswordKey(password, salt), "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(plain);
    }

    private static byte[] decryptWithPassword(String password, byte[] cipherText, byte[] salt, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(derivePasswordKey(password, salt), "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(cipherText);
    }

    private static JSONArray bytesToJsonArray(byte[] bytes) {
        JSONArray array = new JSONArray();
        for (byte value : bytes) {
            array.put(value & 0xFF);
        }
        return array;
    }

    private static byte[] parseBinaryField(JSONObject json, String fieldName) throws JSONException {
        Object value = json.opt(fieldName);
        if (value instanceof JSONArray) {
            return jsonArrayToBytes((JSONArray) value, fieldName);
        }
        if (value instanceof String) {
            try {
                return Base64.decode((String) value, Base64.NO_WRAP);
            } catch (IllegalArgumentException e) {
                throw new JSONException("Invalid base64 in " + fieldName);
            }
        }
        throw new JSONException("Invalid field type for " + fieldName);
    }

    private static byte[] jsonArrayToBytes(JSONArray array, String fieldName) throws JSONException {
        int length = array.length();
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++) {
            int value = array.getInt(i);
            if (value < 0 || value > 255) {
                throw new JSONException("Invalid byte value in " + fieldName + " at index " + i);
            }
            data[i] = (byte) value;
        }
        return data;
    }

    private static byte[] derivePasswordKey(String password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, KEY_TRANSFER_PBKDF2_ITERATIONS, AES_KEY_SIZE_BYTES * 8);
        try {
            try {
                return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(keySpec).getEncoded();
            } catch (GeneralSecurityException ignore) {
                return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(keySpec).getEncoded();
            }
        } finally {
            keySpec.clearPassword();
        }
    }

    private static File encryptBinaryFile(File sourceFile, OutgoingPeerContext context) throws Exception {
        byte[] aesKey = new byte[AES_KEY_SIZE_BYTES];
        new SecureRandom().nextBytes(aesKey);
        byte[] iv = new byte[GCM_IV_BYTES];
        new SecureRandom().nextBytes(iv);
        byte[] keyTo = rsaEncrypt(aesKey, context.peerKey.rsaPublic);
        byte[] keyFrom = rsaEncrypt(aesKey, context.keys.rsaPublic);

        JSONObject header = new JSONObject();
        header.put("v", 1);
        header.put("sender", context.senderUserId);
        header.put("iv", bytesToJsonArray(iv));
        header.put("key_to", bytesToJsonArray(keyTo));
        header.put("key_from", bytesToJsonArray(keyFrom));

        byte[] headerBytes = header.toString(2).getBytes(StandardCharsets.UTF_8);
        File targetFile = createTempBinaryFile(sourceFile.getName());
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));

        try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(sourceFile));
             DataOutputStream outputStream = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(targetFile)))) {
            outputStream.write(ENCRYPTED_FILE_MAGIC);
            outputStream.writeInt(headerBytes.length);
            outputStream.write(headerBytes);
            try (CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
                byte[] buffer = new byte[FILE_BUFFER_SIZE];
                int read;
                while ((read = inputStream.read(buffer)) != -1) {
                    cipherOutputStream.write(buffer, 0, read);
                }
            }
        }
        return targetFile;
    }

    private static void decryptBinaryFile(File sourceFile, File targetFile, EncryptedFileHeader header, byte[] aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(GCM_TAG_BITS, header.iv));
        try (DataInputStream inputStream = new DataInputStream(new BufferedInputStream(new FileInputStream(sourceFile)))) {
            inputStream.skipBytes(ENCRYPTED_FILE_MAGIC.length);
            int headerLength = inputStream.readInt();
            if (headerLength <= 0 || headerLength > FILE_HEADER_LIMIT) {
                throw new IOException("Invalid encrypted file header");
            }
            inputStream.skipBytes(headerLength);
            try (CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
                 BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(targetFile))) {
                byte[] buffer = new byte[FILE_BUFFER_SIZE];
                int read;
                while ((read = cipherInputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, read);
                }
            }
        }
    }

    private static EncryptedFileHeader readEncryptedFileHeader(File file) throws Exception {
        try (DataInputStream inputStream = new DataInputStream(new BufferedInputStream(new FileInputStream(file)))) {
            byte[] magic = new byte[ENCRYPTED_FILE_MAGIC.length];
            if (inputStream.read(magic) != magic.length) {
                return null;
            }
            for (int i = 0; i < magic.length; i++) {
                if (magic[i] != ENCRYPTED_FILE_MAGIC[i]) {
                    return null;
                }
            }
            int headerLength = inputStream.readInt();
            if (headerLength <= 0 || headerLength > FILE_HEADER_LIMIT) {
                return null;
            }
            byte[] headerBytes = new byte[headerLength];
            inputStream.readFully(headerBytes);
            JSONObject header = new JSONObject(new String(headerBytes, StandardCharsets.UTF_8));
            return new EncryptedFileHeader(
                    parseBinaryField(header, "iv"),
                    parseBinaryField(header, "key_to"),
                    parseBinaryField(header, "key_from")
            );
        }
    }

    private static DisplayResult getDisplayTextFromEncryptedDocument(int account, TLRPC.Message message, long senderUserId) {
        if (message.params != null) {
            String previewText = message.params.get(PARAM_PREVIEW_TEXT);
            if (!TextUtils.isEmpty(previewText)) {
                return new DisplayResult(previewText, LocaleController.getString(R.string.EncryptionMessageDecrypted), true, false);
            }
        }
        File localFile = getLocalMessageFile(account, message);
        if (localFile == null || !localFile.exists()) {
            TLRPC.Document document = MessageObject.getMedia(message) != null ? MessageObject.getMedia(message).document : null;
            if (document != null) {
                String attachFileName = FileLoader.getAttachFileName(document);
                FileLoader fileLoader = FileLoader.getInstance(account);
                if (!fileLoader.isLoadingFile(attachFileName)) {
                    fileLoader.loadFile(document, message, FileLoader.PRIORITY_HIGH, 0);
                }
            }
            return new DisplayResult(LocaleController.getString(R.string.Loading), LocaleController.getString(R.string.EncryptionMessageDecrypted), true, false);
        }
        try {
            String text = readUtf8File(localFile);
            if (TextUtils.isEmpty(text)) {
                return new DisplayResult("", LocaleController.getString(R.string.EncryptionMessageDecryptError), true, true);
            }
            if (text.startsWith(ENCRYPTION_PREFIX)) {
                return getDisplayText(account, senderUserId, text);
            }
            return new DisplayResult(text, LocaleController.getString(R.string.EncryptionMessageDecrypted), true, false);
        } catch (Exception e) {
            return new DisplayResult("", LocaleController.getString(R.string.EncryptionMessageDecryptError), true, true);
        }
    }

    private static File getLocalMessageFile(int account, TLRPC.Message message) {
        if (message == null) {
            return null;
        }
        if (!TextUtils.isEmpty(message.attachPath)) {
            File attachFile = new File(message.attachPath);
            if (attachFile.exists()) {
                return attachFile;
            }
        }
        File file = FileLoader.getInstance(account).getPathToMessage(message);
        if (file != null && file.exists()) {
            return file;
        }
        return null;
    }

    private static String readUtf8File(File file) throws IOException {
        try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buffer = new byte[(int) file.length()];
            int offset = 0;
            int read;
            while (offset < buffer.length && (read = inputStream.read(buffer, offset, buffer.length - offset)) != -1) {
                offset += read;
            }
            return new String(buffer, 0, offset, StandardCharsets.UTF_8);
        }
    }

    private static File createTempTextFile(String prefix, String text) throws IOException {
        File file = File.createTempFile(prefix, ".txt", FileLoader.getDirectory(FileLoader.MEDIA_DIR_CACHE));
        try (FileOutputStream outputStream = new FileOutputStream(file)) {
            outputStream.write(text.getBytes(StandardCharsets.UTF_8));
        }
        return file;
    }

    private static File createTempKeyTransferFile(String transferId) throws IOException {
        File directory = FileLoader.getDirectory(FileLoader.MEDIA_DIR_CACHE);
        File file = new File(directory, KEY_TRANSFER_FILE_PREFIX + transferId + KEY_TRANSFER_FILE_EXTENSION);
        int suffix = 1;
        while (file.exists()) {
            file = new File(directory, KEY_TRANSFER_FILE_PREFIX + transferId + "_" + suffix + KEY_TRANSFER_FILE_EXTENSION);
            suffix++;
        }
        return file;
    }

    private static File createTempBinaryFile(String sourceName) throws IOException {
        String suffix = ".enc";
        int dot = sourceName == null ? -1 : sourceName.lastIndexOf('.');
        if (dot >= 0 && dot < sourceName.length() - 1) {
            suffix = sourceName.substring(dot) + ".enc";
        }
        return File.createTempFile("enc_media_", suffix, FileLoader.getDirectory(FileLoader.MEDIA_DIR_CACHE));
    }

    private static void replaceFile(File source, File target) throws IOException {
        if (target.exists() && !target.delete()) {
            throw new IOException("Unable to delete old file");
        }
        if (!source.renameTo(target)) {
            try (BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(source));
                 BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(target))) {
                byte[] buffer = new byte[FILE_BUFFER_SIZE];
                int read;
                while ((read = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, read);
                }
            }
            source.delete();
        }
    }

    private static PublicKeyInfo getPublicKey(int account, long userId) throws IOException, JSONException, GeneralSecurityException {
        PublicKeyInfo cached = getCachedPublicKey(account, userId);
        if (cached != null) {
            return cached;
        }
        String server = getServerAddress(account);
        if (TextUtils.isEmpty(server)) {
            return null;
        }
        JSONObject response = getJson(server + "/api/v1/get_public_key/" + userId);
        if (response == null) {
            return null;
        }
        if (response.has("error")) {
            return null;
        }
        String publicKeyValue = response.optString("public_key", null);
        if (TextUtils.isEmpty(publicKeyValue)) {
            return null;
        }
        PublicKeyInfo info = parsePublicKey(publicKeyValue);
        if (info != null) {
            saveCachedPublicKey(account, userId, publicKeyValue, info);
        }
        return info;
    }

    private static PublicKeyInfo parsePublicKey(String publicKeyValue) throws JSONException, GeneralSecurityException {
        if (publicKeyValue.startsWith("{")) {
            JSONObject obj = new JSONObject(publicKeyValue);
            String rsaB64 = obj.optString("rsa", null);
            if (TextUtils.isEmpty(rsaB64)) {
                return null;
            }
            PublicKey rsa = decodePublicKey("RSA", rsaB64);
            return new PublicKeyInfo(rsa);
        } else {
            PublicKey rsa = decodePublicKey("RSA", publicKeyValue);
            return new PublicKeyInfo(rsa);
        }
    }

    private static PublicKeyInfo getCachedPublicKey(int account, long userId) {
        String mapKey = cacheKey(account, userId);
        String cached = publicKeyCache.get(mapKey);
        if (cached == null) {
            String cacheKey = keyForAccount("public_keys", account);
            String json = getPrefs(PREF_CACHE).getString(cacheKey, null);
            if (!TextUtils.isEmpty(json)) {
                try {
                    JSONObject obj = new JSONObject(json);
                    cached = obj.optString(String.valueOf(userId), null);
                    if (!TextUtils.isEmpty(cached)) {
                        publicKeyCache.put(mapKey, cached);
                    }
                } catch (JSONException ignored) {
                }
            }
        }
        if (TextUtils.isEmpty(cached)) {
            return null;
        }
        try {
            return parsePublicKey(cached);
        } catch (Exception e) {
            return null;
        }
    }

    private static void saveCachedPublicKey(int account, long userId, String publicKeyValue, PublicKeyInfo info) {
        String mapKey = cacheKey(account, userId);
        publicKeyCache.put(mapKey, publicKeyValue);
        String cacheKey = keyForAccount("public_keys", account);
        try {
            JSONObject obj = new JSONObject(getPrefs(PREF_CACHE).getString(cacheKey, "{}"));
            obj.put(String.valueOf(userId), publicKeyValue);
            getPrefs(PREF_CACHE).edit().putString(cacheKey, obj.toString()).apply();
        } catch (JSONException ignored) {
        }
    }

    private static String cacheKey(int account, long userId) {
        return account + ":" + userId;
    }

    private static JSONObject postJson(String url, JSONObject payload) throws IOException, JSONException {
        FileLog.d("EncryptionManager POST " + url);
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setConnectTimeout(NETWORK_TIMEOUT_MS);
        connection.setReadTimeout(NETWORK_TIMEOUT_MS);
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json");
        byte[] out = payload.toString().getBytes(StandardCharsets.UTF_8);
        connection.setFixedLengthStreamingMode(out.length);
        connection.connect();
        try (OutputStream os = connection.getOutputStream()) {
            os.write(out);
        }
        return readResponse(connection);
    }

    private static JSONObject getJson(String url) throws IOException, JSONException {
        FileLog.d("EncryptionManager GET " + url);
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setConnectTimeout(NETWORK_TIMEOUT_MS);
        connection.setReadTimeout(NETWORK_TIMEOUT_MS);
        connection.setRequestMethod("GET");
        connection.connect();
        return readResponse(connection);
    }

    private static JSONObject readResponse(HttpURLConnection connection) throws IOException, JSONException {
        int code = connection.getResponseCode();
        InputStream stream = code >= 200 && code < 300 ? connection.getInputStream() : connection.getErrorStream();
        if (stream == null) {
            JSONObject error = new JSONObject();
            error.put("error", "HTTP " + code);
            return error;
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line);
            }
            String body = builder.toString();
            FileLog.d("EncryptionManager response " + code + ": " + body);
            if (TextUtils.isEmpty(body)) {
                JSONObject error = new JSONObject();
                error.put("error", "HTTP " + code);
                return error;
            }
            try {
                JSONObject json = new JSONObject(body);
                json.put("status_code", code);
                return json;
            } catch (JSONException e) {
                JSONObject error = new JSONObject();
                error.put("status_code", code);
                error.put("raw", body);
                error.put("error", "Invalid JSON response");
                return error;
            }
        } finally {
            connection.disconnect();
        }
    }

    public static void showEncryptionWarning(String text) {
        AndroidUtilities.runOnUIThread(() ->
            Toast.makeText(ApplicationLoader.applicationContext, text, Toast.LENGTH_LONG).show()
        );
    }

    private static void sendKeyTransferAck(int account, String transferId) {
        AndroidUtilities.runOnUIThread(() -> {
            long selfId = UserConfig.getInstance(account).getClientUserId();
            if (selfId == 0) {
                return;
            }
            HashMap<String, String> params = new HashMap<>();
            params.put(PARAM_SKIP_AUTO_ENCRYPTION, "1");
            SendMessagesHelper.SendMessageParams sendMessageParams = SendMessagesHelper.SendMessageParams.of(
                    KEY_TRANSFER_ACK_PREFIX + transferId,
                    selfId,
                    null,
                    null,
                    null,
                    true,
                    null,
                    null,
                    params,
                    false,
                    0,
                    0,
                    null,
                    false
            );
            AccountInstance.getInstance(account).getSendMessagesHelper().sendMessage(sendMessageParams);
        });
    }

    private static void validateImportedKeyPair(String publicKeyB64, String privateKeyB64) throws GeneralSecurityException {
        PublicKey publicKey = decodePublicKey("RSA", publicKeyB64);
        PrivateKey privateKey = decodePrivateKey("RSA", privateKeyB64);
        byte[] probe = new byte[32];
        new SecureRandom().nextBytes(probe);
        byte[] encrypted = rsaEncrypt(probe, publicKey);
        byte[] decrypted = rsaDecryptOrNull(encrypted, privateKey);
        if (decrypted == null || decrypted.length != probe.length) {
            throw new GeneralSecurityException("Invalid key pair");
        }
        for (int i = 0; i < probe.length; i++) {
            if (probe[i] != decrypted[i]) {
                throw new GeneralSecurityException("Invalid key pair");
            }
        }
    }

    private static String generateKeyTransferPassword() {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder builder = new StringBuilder(KEY_TRANSFER_PASSWORD_GROUPS * (KEY_TRANSFER_PASSWORD_GROUP_SIZE + 1));
        for (int group = 0; group < KEY_TRANSFER_PASSWORD_GROUPS; group++) {
            if (group > 0) {
                builder.append('-');
            }
            for (int i = 0; i < KEY_TRANSFER_PASSWORD_GROUP_SIZE; i++) {
                int index = secureRandom.nextInt(KEY_TRANSFER_PASSWORD_ALPHABET.length());
                builder.append(KEY_TRANSFER_PASSWORD_ALPHABET.charAt(index));
            }
        }
        return builder.toString();
    }

    private static String normalizeKeyTransferPassword(String password) {
        if (TextUtils.isEmpty(password)) {
            return "";
        }
        StringBuilder builder = new StringBuilder(password.length());
        for (int i = 0; i < password.length(); i++) {
            char ch = password.charAt(i);
            if (Character.isLetterOrDigit(ch)) {
                builder.append(Character.toUpperCase(ch));
            }
        }
        return builder.toString();
    }

    private static String generateTransferId() {
        byte[] bytes = new byte[8];
        new SecureRandom().nextBytes(bytes);
        return Utilities.bytesToHex(bytes).toLowerCase();
    }

    private static class KeyBundle {
        final PublicKey rsaPublic;
        final PrivateKey rsaPrivate;
        final String rsaPublicB64;

        KeyBundle(PublicKey rsaPublic, PrivateKey rsaPrivate, String rsaPublicB64) {
            this.rsaPublic = rsaPublic;
            this.rsaPrivate = rsaPrivate;
            this.rsaPublicB64 = rsaPublicB64;
        }
    }

    private static class PublicKeyInfo {
        final PublicKey rsaPublic;

        PublicKeyInfo(PublicKey rsaPublic) {
            this.rsaPublic = rsaPublic;
        }
    }

    private static class OutgoingPeerContext {
        final KeyBundle keys;
        final PublicKeyInfo peerKey;
        final long senderUserId;

        OutgoingPeerContext(KeyBundle keys, PublicKeyInfo peerKey, long senderUserId) {
            this.keys = keys;
            this.peerKey = peerKey;
            this.senderUserId = senderUserId;
        }
    }

    private static class EncryptedFileHeader {
        final byte[] iv;
        final byte[] keyTo;
        final byte[] keyFrom;

        EncryptedFileHeader(byte[] iv, byte[] keyTo, byte[] keyFrom) {
            this.iv = iv;
            this.keyTo = keyTo;
            this.keyFrom = keyFrom;
        }
    }
}
