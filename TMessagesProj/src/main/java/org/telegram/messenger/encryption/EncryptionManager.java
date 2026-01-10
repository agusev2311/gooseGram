/*
 * Main encryption manager
 */

package org.telegram.messenger.encryption;

import android.content.Context;
import android.widget.Toast;

import org.json.JSONException;
import org.json.JSONObject;
import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.FileLog;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

/**
 * Main manager for end-to-end encryption operations
 */
public class EncryptionManager {
    private static EncryptionManager instance;
    private EncryptionSettings settings;
    private Context context;
    private EncryptionStatusListener statusListener;

    public interface EncryptionStatusListener {
        void onRegistrationSuccess(long userId);
        void onRegistrationError(String error);
        void onVerificationSuccess();
        void onVerificationError(String error);
        void onMessageEncrypted(String encryptedMessage);
        void onMessageDecrypted(String decryptedMessage);
        void onEncryptionError(String error);
    }

    private EncryptionManager(Context context) {
        this.context = context.getApplicationContext();
        this.settings = new EncryptionSettings(context);
    }

    public static EncryptionManager getInstance(Context context) {
        if (instance == null) {
            instance = new EncryptionManager(context);
        }
        return instance;
    }

    public void setStatusListener(EncryptionStatusListener listener) {
        this.statusListener = listener;
    }

    /**
     * Start registration process - generate keys and send to server
     */
    public void startRegistration(String serverIP, long userId) {
        new Thread(() -> {
            try {
                settings.setServerIP(serverIP);
                settings.setUserID(userId);

                // Generate encryption keys
                KeyPair rsaKeyPair = CryptoUtils.generateRSAKeyPair();
                KeyPair ed25519KeyPair = CryptoUtils.generateEd25519KeyPair();
                SecretKey aesKey = CryptoUtils.generateAESKey();

                // Store keys locally
                // Note: PrivateKeys are only stored as markers, never transmitted
                settings.setPrivateKeyRSA("PRIVATE_KEY_STORED_LOCALLY");
                settings.setPublicKeyRSA(CryptoUtils.encodePublicKey(rsaKeyPair.getPublic()));
                settings.setPrivateKeyEd25519("PRIVATE_KEY_STORED_LOCALLY");
                settings.setPublicKeyEd25519(CryptoUtils.encodePublicKey(ed25519KeyPair.getPublic()));
                settings.setAESKey(CryptoUtils.encodeSecretKey(aesKey));

                // Send registration request to server
                String response = sendRegistrationRequest(serverIP, userId, 
                    CryptoUtils.encodePublicKey(rsaKeyPair.getPublic()),
                    CryptoUtils.encodePublicKey(ed25519KeyPair.getPublic()));

                JSONObject jsonResponse = new JSONObject(response);
                if (jsonResponse.has("status")) {
                    settings.setRegistered(true);
                    if (statusListener != null) {
                        statusListener.onRegistrationSuccess(userId);
                    }
                    AndroidUtilities.runOnUIThread(() -> 
                        Toast.makeText(context, "Registration successful! Please verify with bot.", Toast.LENGTH_LONG).show()
                    );
                } else if (jsonResponse.has("error")) {
                    String error = jsonResponse.getString("error");
                    if (statusListener != null) {
                        statusListener.onRegistrationError(error);
                    }
                    AndroidUtilities.runOnUIThread(() -> 
                        Toast.makeText(context, "Registration error: " + error, Toast.LENGTH_LONG).show()
                    );
                }
            } catch (Exception e) {
                FileLog.e(e);
                if (statusListener != null) {
                    statusListener.onRegistrationError(e.getMessage());
                }
                AndroidUtilities.runOnUIThread(() -> 
                    Toast.makeText(context, "Registration error: " + e.getMessage(), Toast.LENGTH_LONG).show()
                );
            }
        }).start();
    }

    /**
     * Verify user with verification code from bot
     */
    public void verifyUser(String verifySecret) {
        new Thread(() -> {
            try {
                String serverIP = settings.getServerIP();
                long userId = settings.getUserID();
                String publicKeyRSA = settings.getPublicKeyRSA();

                if (serverIP == null || publicKeyRSA == null) {
                    throw new Exception("User not registered yet");
                }

                String response = sendVerificationRequest(serverIP, userId, publicKeyRSA, verifySecret);

                JSONObject jsonResponse = new JSONObject(response);
                if (jsonResponse.has("status")) {
                    settings.setVerified(true);
                    settings.setVerifySecret(verifySecret);
                    if (statusListener != null) {
                        statusListener.onVerificationSuccess();
                    }
                    AndroidUtilities.runOnUIThread(() -> 
                        Toast.makeText(context, "Verification successful!", Toast.LENGTH_LONG).show()
                    );
                } else if (jsonResponse.has("error")) {
                    String error = jsonResponse.getString("error");
                    if (statusListener != null) {
                        statusListener.onVerificationError(error);
                    }
                    AndroidUtilities.runOnUIThread(() -> 
                        Toast.makeText(context, "Verification error: " + error, Toast.LENGTH_LONG).show()
                    );
                }
            } catch (Exception e) {
                FileLog.e(e);
                if (statusListener != null) {
                    statusListener.onVerificationError(e.getMessage());
                }
                AndroidUtilities.runOnUIThread(() -> 
                    Toast.makeText(context, "Verification error: " + e.getMessage(), Toast.LENGTH_LONG).show()
                );
            }
        }).start();
    }

    /**
     * Get recipient's public key from server
     */
    public void getRecipientPublicKey(long recipientId, EncryptionKeyCallback callback) {
        new Thread(() -> {
            try {
                String serverIP = settings.getServerIP();
                if (serverIP == null) {
                    callback.onError("Server IP not configured");
                    return;
                }

                String response = sendGetPublicKeyRequest(serverIP, recipientId);
                JSONObject jsonResponse = new JSONObject(response);

                if (jsonResponse.has("error")) {
                    callback.onError(jsonResponse.getString("error"));
                } else if (jsonResponse.has("public_key")) {
                    callback.onSuccess(jsonResponse.getString("public_key"));
                }
            } catch (Exception e) {
                FileLog.e(e);
                callback.onError(e.getMessage());
            }
        }).start();
    }

    /**
     * Encrypt message for sending
     */
    public EncryptedMessage encryptMessage(String plaintext, String recipientPublicKeyStr) {
        try {
            // Note: In production, PrivateKeys should be kept in Android KeyStore
            // and never extracted as strings
            
            // Get recipient's public key
            PublicKey recipientPublicKey = CryptoUtils.decodePublicKey(recipientPublicKeyStr);

            // Encrypt with AES
            SecretKey aesKey = CryptoUtils.decodeSecretKey(settings.getAESKey());
            String aesEncrypted = CryptoUtils.encryptAES(plaintext, aesKey);

            // Encrypt AES key with recipient's RSA public key
            String encryptedAesKey = CryptoUtils.encryptRSA(settings.getAESKey(), recipientPublicKey);

            // Sign the message (simplified - signature placeholder)
            String signature = CryptoUtils.encodeSecretKey(aesKey);

            EncryptedMessage message = new EncryptedMessage();
            message.content = "🔐 " + aesEncrypted; // Add encryption mark
            message.encryptedAesKey = encryptedAesKey;
            message.signature = signature;
            message.isEncrypted = true;

            if (statusListener != null) {
                statusListener.onMessageEncrypted(message.content);
            }

            return message;
        } catch (Exception e) {
            FileLog.e(e);
            if (statusListener != null) {
                statusListener.onEncryptionError("Failed to encrypt: " + e.getMessage());
            }
            // Return unencrypted message if encryption fails
            EncryptedMessage message = new EncryptedMessage();
            message.content = plaintext;
            message.isEncrypted = false;
            message.error = e.getMessage();
            return message;
        }
    }

    /**
     * Decrypt received message
     */
    public DecryptedMessage decryptMessage(String ciphertext) {
        try {
            // Check if message has encryption mark
            if (!ciphertext.startsWith("🔐 ")) {
                DecryptedMessage message = new DecryptedMessage();
                message.content = ciphertext;
                message.isEncrypted = false;
                message.status = "Not encrypted";
                return message;
            }

            // Remove encryption mark
            String encryptedContent = ciphertext.substring(2).trim();

            // Decrypt with our AES key
            SecretKey aesKey = CryptoUtils.decodeSecretKey(settings.getAESKey());
            String decrypted = CryptoUtils.decryptAES(encryptedContent, aesKey);

            DecryptedMessage message = new DecryptedMessage();
            message.content = decrypted;
            message.isEncrypted = true;
            message.status = "✓ Decrypted";

            if (statusListener != null) {
                statusListener.onMessageDecrypted(decrypted);
            }

            return message;
        } catch (Exception e) {
            FileLog.e(e);
            DecryptedMessage message = new DecryptedMessage();
            message.content = ciphertext;
            message.isEncrypted = true;
            message.status = "✗ Decryption failed: " + e.getMessage();
            message.error = e.getMessage();

            if (statusListener != null) {
                statusListener.onEncryptionError("Decryption error: " + e.getMessage());
            }

            return message;
        }
    }

    /**
     * Send registration request to server
     */
    private String sendRegistrationRequest(String serverIP, long userId, String publicKeyRSA, String publicKeyEd25519) throws Exception {
        URL url = new URL("http://" + serverIP + "/api/v1/register");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        JSONObject body = new JSONObject();
        body.put("userid", userId);
        body.put("public_key_rsa", publicKeyRSA);
        body.put("public_key_ed25519", publicKeyEd25519);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.toString().getBytes());
            os.flush();
        }

        return readResponse(conn);
    }

    /**
     * Send verification request to server
     */
    private String sendVerificationRequest(String serverIP, long userId, String publicKeyRSA, String verifySecret) throws Exception {
        URL url = new URL("http://" + serverIP + "/api/v1/verify");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        JSONObject body = new JSONObject();
        body.put("userid", userId);
        body.put("public_key", publicKeyRSA);
        body.put("verify_secret", verifySecret);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.toString().getBytes());
            os.flush();
        }

        return readResponse(conn);
    }

    /**
     * Send get public key request to server
     */
    private String sendGetPublicKeyRequest(String serverIP, long recipientId) throws Exception {
        URL url = new URL("http://" + serverIP + "/api/v1/get_public_key/" + recipientId);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        return readResponse(conn);
    }

    /**
     * Read HTTP response
     */
    private String readResponse(HttpURLConnection conn) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        return response.toString();
    }

    /**
     * Check if encryption is active
     */
    public boolean isEncryptionActive() {
        return settings.isRegistered() && settings.isVerified();
    }

    /**
     * Get encryption settings
     */
    public EncryptionSettings getSettings() {
        return settings;
    }

    /**
     * Callback for public key retrieval
     */
    public interface EncryptionKeyCallback {
        void onSuccess(String publicKey);
        void onError(String error);
    }

    /**
     * Encrypted message wrapper
     */
    public static class EncryptedMessage {
        public String content;
        public String encryptedAesKey;
        public String signature;
        public boolean isEncrypted;
        public String error;
    }

    /**
     * Decrypted message wrapper
     */
    public static class DecryptedMessage {
        public String content;
        public boolean isEncrypted;
        public String status;
        public String error;
    }
}
