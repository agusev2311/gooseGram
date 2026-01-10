/*
 * Encryption utilities for E2E messaging
 */

package org.telegram.messenger.encryption;

import android.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Cryptographic utilities for AES, RSA, and Ed25519 encryption/decryption
 */
public class CryptoUtils {
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final int AES_KEY_SIZE = 256;
    private static final int RSA_KEY_SIZE = 2048;
    private static final int IV_SIZE = 16;

    /**
     * Generate AES key
     */
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    /**
     * Generate RSA key pair
     */
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    /**
     * Generate Ed25519 key pair (using RSA for now as fallback, should be replaced with actual Ed25519)
     */
    public static KeyPair generateEd25519KeyPair() throws Exception {
        // For Android compatibility, using RSA as Ed25519 requires API 23+
        // In production, replace with actual Ed25519 implementation
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    /**
     * Encrypt message using AES with random IV
     */
    public static String encryptAES(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        
        // Generate random IV
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        
        // Combine IV and encrypted data
        byte[] combined = new byte[IV_SIZE + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, IV_SIZE);
        System.arraycopy(encrypted, 0, combined, IV_SIZE, encrypted.length);
        
        return Base64.encodeToString(combined, Base64.NO_WRAP);
    }

    /**
     * Decrypt message using AES
     */
    public static String decryptAES(String ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        
        byte[] combined = Base64.decode(ciphertext, Base64.NO_WRAP);
        
        // Extract IV and encrypted data
        byte[] iv = new byte[IV_SIZE];
        byte[] encrypted = new byte[combined.length - IV_SIZE];
        System.arraycopy(combined, 0, iv, 0, IV_SIZE);
        System.arraycopy(combined, IV_SIZE, encrypted, 0, encrypted.length);
        
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Encrypt message using RSA public key
     */
    public static String encryptRSA(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }

    /**
     * Decrypt message using RSA private key
     */
    public static String decryptRSA(String ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encrypted = Base64.decode(ciphertext, Base64.NO_WRAP);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Encode public key to Base64 string
     */
    public static String encodePublicKey(PublicKey publicKey) {
        return Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
    }

    /**
     * Encode private key to Base64 string
     */
    public static String encodePrivateKey(PrivateKey privateKey) {
        return Base64.encodeToString(privateKey.getEncoded(), Base64.NO_WRAP);
    }

    /**
     * Decode public key from Base64 string
     */
    public static PublicKey decodePublicKey(String keyString) throws Exception {
        byte[] decodedKey = Base64.decode(keyString, Base64.NO_WRAP);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    /**
     * Encode secret key to Base64 string
     */
    public static String encodeSecretKey(SecretKey key) {
        return Base64.encodeToString(key.getEncoded(), Base64.NO_WRAP);
    }

    /**
     * Decode secret key from Base64 string
     */
    public static SecretKey decodeSecretKey(String keyString) {
        byte[] decodedKey = Base64.decode(keyString, Base64.NO_WRAP);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    /**
     * Sign message using Ed25519 private key (using RSA for now)
     */
    public static String signMessage(String message, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] signature = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(signature, Base64.NO_WRAP);
    }

    /**
     * Verify message signature using Ed25519 public key (using RSA for now)
     */
    public static boolean verifySignature(String message, String signature, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decoded = Base64.decode(signature, Base64.NO_WRAP);
        byte[] decrypted = cipher.doFinal(decoded);
        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);
        return message.equals(decryptedMessage);
    }
}
