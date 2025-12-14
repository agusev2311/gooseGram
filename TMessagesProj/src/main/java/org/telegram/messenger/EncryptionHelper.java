package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

public class EncryptionHelper {
    private static final String PREFS_NAME = "encryption_keys";
    private static final String PUBLIC_KEY = "rsa_public";
    private static final String PRIVATE_KEY = "rsa_private";

    private static final String REMOTE_KEYS_PREFS = "remote_public_keys";

    public static PublicKey getPublicKey(Context context) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String pub = prefs.getString(PUBLIC_KEY, null);
        if (pub == null) return null;
        byte[] keyBytes = Base64.decode(pub, Base64.DEFAULT);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PrivateKey getPrivateKey(Context context) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String priv = prefs.getString(PRIVATE_KEY, null);
        if (priv == null) return null;
        byte[] keyBytes = Base64.decode(priv, Base64.DEFAULT);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static String encrypt(String plainText, Context context) throws Exception {
        PublicKey publicKey = getPublicKey(context);
        if (publicKey == null) throw new Exception("Public key not found");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.encodeToString(encryptedBytes, Base64.NO_WRAP);
    }

    public static String decrypt(String encrypted, Context context) throws Exception {
        PrivateKey privateKey = getPrivateKey(context);
        if (privateKey == null) throw new Exception("Private key not found");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.decode(encrypted, Base64.NO_WRAP));
        return new String(decryptedBytes, "UTF-8");
    }

    public interface PublicKeyFetchCallback {
        void onSuccess(PublicKey key);
        void onError(Exception e);
    }

    public static void getRemotePublicKey(final Context context, final long userId, final PublicKeyFetchCallback cb) {
        // check cache first
        try {
            SharedPreferences prefs = context.getSharedPreferences(REMOTE_KEYS_PREFS, Context.MODE_PRIVATE);
            String b64 = prefs.getString("pub_" + userId, null);
            if (b64 != null) {
                byte[] keyBytes = android.util.Base64.decode(b64, android.util.Base64.DEFAULT);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey pub = kf.generatePublic(spec);
                cb.onSuccess(pub);
                return;
            }
        } catch (Exception e) {
            // fall through to fetch
        }

        // fetch from server
        ServerClient.getPublicKey(context, userId, new ServerClient.StringCallback() {
            @Override
            public void onSuccess(String body) {
                try {
                    // expect JSON {"public_key": "..."} or plain string
                    String pubPem = body;
                    // try to extract Base64 part if PEM
                    if (pubPem.contains("-----BEGIN")) {
                        pubPem = pubPem.replaceAll("(?s)-----BEGIN.*?-----", "");
                        pubPem = pubPem.replaceAll("(?s)-----END.*?-----", "");
                        pubPem = pubPem.replaceAll("\\s+", "");
                    }
                    byte[] keyBytes = android.util.Base64.decode(pubPem, android.util.Base64.DEFAULT);
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    PublicKey pub = kf.generatePublic(spec);
                    // cache
                    try {
                        context.getSharedPreferences(REMOTE_KEYS_PREFS, Context.MODE_PRIVATE).edit().putString("pub_" + userId, android.util.Base64.encodeToString(keyBytes, android.util.Base64.NO_WRAP)).apply();
                    } catch (Throwable ignore) {}
                    cb.onSuccess(pub);
                } catch (Exception e) {
                    cb.onError(e);
                }
            }

            @Override
            public void onError(Exception e) {
                cb.onError(e);
            }
        });
    }

    public interface EncryptBothCallback {
        void onResult(boolean encrypted, String senderEncrypted, String recipientEncrypted);
        void onError(Exception e);
    }

    public static void encryptForSenderAndRecipient(final Context context, final String plainText, final long recipientId, final EncryptBothCallback cb) {
        try {
            final PublicKey senderPub = getPublicKey(context);
            if (senderPub == null) {
                cb.onResult(false, null, null);
                return;
            }
            // fetch remote recipient key asynchronously
            getRemotePublicKey(context, recipientId, new PublicKeyFetchCallback() {
                @Override
                public void onSuccess(PublicKey recipientPub) {
                    try {
                        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipher.init(Cipher.ENCRYPT_MODE, senderPub);
                        byte[] enc1 = cipher.doFinal(plainText.getBytes("UTF-8"));
                        String s1 = android.util.Base64.encodeToString(enc1, android.util.Base64.NO_WRAP);

                        cipher.init(Cipher.ENCRYPT_MODE, recipientPub);
                        byte[] enc2 = cipher.doFinal(plainText.getBytes("UTF-8"));
                        String s2 = android.util.Base64.encodeToString(enc2, android.util.Base64.NO_WRAP);

                        cb.onResult(true, s1, s2);
                    } catch (Exception e) {
                        cb.onError(e);
                    }
                }

                @Override
                public void onError(Exception e) {
                    // recipient not registered or error -> do not encrypt
                    cb.onResult(false, null, null);
                }
            });
        } catch (Exception e) {
            cb.onError(e);
        }
    }
}
