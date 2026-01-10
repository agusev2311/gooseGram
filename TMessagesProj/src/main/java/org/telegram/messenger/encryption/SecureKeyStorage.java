/*
 * Secure key storage utilities
 */

package org.telegram.messenger.encryption;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.annotation.RequiresApi;

import org.telegram.messenger.FileLog;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Secure key storage using Android KeyStore (API 23+)
 */
public class SecureKeyStorage {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ENCRYPTION_KEY_ALIAS = "e2e_master_key";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";

    private KeyStore keyStore;
    private Context context;

    public SecureKeyStorage(Context context) {
        this.context = context;
        try {
            initKeyStore();
        } catch (Exception e) {
            FileLog.e("Failed to initialize KeyStore", e);
        }
    }

    /**
     * Initialize Android KeyStore
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private void initKeyStore() throws KeyStoreException, CertificateException, 
                                       IOException, NoSuchAlgorithmException {
        keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        // Create master encryption key if not exists
        if (!keyStore.containsAlias(ENCRYPTION_KEY_ALIAS)) {
            try {
                createMasterKey();
            } catch (NoSuchProviderException | InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Create master encryption key for storing other keys
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private void createMasterKey() throws NoSuchProviderException, 
                                         NoSuchAlgorithmException,
                                         InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);

        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
            ENCRYPTION_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build();

        keyGenerator.init(spec);
        keyGenerator.generateKey();
    }

    /**
     * Get master encryption key
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private SecretKey getMasterKey() throws KeyStoreException, 
                                           UnrecoverableKeyException, 
                                           NoSuchAlgorithmException {
        return (SecretKey) keyStore.getKey(ENCRYPTION_KEY_ALIAS, null);
    }

    /**
     * Encrypt data using master key
     */
    public byte[] encryptData(byte[] data) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            FileLog.w("Android KeyStore not available, returning unencrypted data");
            return data;
        }

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            SecretKey key = getMasterKey();
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] iv = cipher.getIV();
            byte[] encryptedData = cipher.doFinal(data);

            // Combine IV + encrypted data
            byte[] result = new byte[GCM_IV_LENGTH + encryptedData.length];
            System.arraycopy(iv, 0, result, 0, GCM_IV_LENGTH);
            System.arraycopy(encryptedData, 0, result, GCM_IV_LENGTH, encryptedData.length);

            return result;
        } catch (Exception e) {
            FileLog.e("Encryption failed", e);
            return null;
        }
    }

    /**
     * Decrypt data using master key
     */
    public byte[] decryptData(byte[] encryptedData) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            FileLog.w("Android KeyStore not available, returning as-is");
            return encryptedData;
        }

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            SecretKey key = getMasterKey();

            // Extract IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(encryptedData, 0, iv, 0, GCM_IV_LENGTH);

            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            // Decrypt
            byte[] actualEncrypted = new byte[encryptedData.length - GCM_IV_LENGTH];
            System.arraycopy(encryptedData, GCM_IV_LENGTH, actualEncrypted, 0, 
                           actualEncrypted.length);

            return cipher.doFinal(actualEncrypted);
        } catch (Exception e) {
            FileLog.e("Decryption failed", e);
            return null;
        }
    }

    /**
     * Check if Android KeyStore is available
     */
    public static boolean isAvailable() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }
}
