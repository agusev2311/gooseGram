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
}
