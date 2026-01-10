/*
 * Encryption settings management
 */

package org.telegram.messenger.encryption;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Manages encryption-related settings and configuration
 */
public class EncryptionSettings {
    private static final String PREFS_NAME = "encryption_settings";
    private static final String KEY_SERVER_IP = "server_ip";
    private static final String KEY_USER_ID = "user_id";
    private static final String KEY_IS_REGISTERED = "is_registered";
    private static final String KEY_IS_VERIFIED = "is_verified";
    private static final String KEY_PRIVATE_KEY_RSA = "private_key_rsa";
    private static final String KEY_PUBLIC_KEY_RSA = "public_key_rsa";
    private static final String KEY_PRIVATE_KEY_ED25519 = "private_key_ed25519";
    private static final String KEY_PUBLIC_KEY_ED25519 = "public_key_ed25519";
    private static final String KEY_AES_KEY = "aes_key";
    private static final String KEY_VERIFY_SECRET = "verify_secret";

    private SharedPreferences preferences;
    private Context context;

    public EncryptionSettings(Context context) {
        this.context = context;
        this.preferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    /**
     * Get server IP address
     */
    public String getServerIP() {
        return preferences.getString(KEY_SERVER_IP, null);
    }

    /**
     * Set server IP address and clear cache if changed
     */
    public void setServerIP(String ip) {
        String oldIp = getServerIP();
        if (oldIp != null && !oldIp.equals(ip)) {
            // IP changed - clear cache but keep keys
            clearCache();
        }
        preferences.edit().putString(KEY_SERVER_IP, ip).apply();
    }

    /**
     * Get user ID
     */
    public long getUserID() {
        return preferences.getLong(KEY_USER_ID, -1);
    }

    /**
     * Set user ID
     */
    public void setUserID(long userId) {
        preferences.edit().putLong(KEY_USER_ID, userId).apply();
    }

    /**
     * Check if user is registered
     */
    public boolean isRegistered() {
        return preferences.getBoolean(KEY_IS_REGISTERED, false);
    }

    /**
     * Set registration status
     */
    public void setRegistered(boolean registered) {
        preferences.edit().putBoolean(KEY_IS_REGISTERED, registered).apply();
    }

    /**
     * Check if user is verified
     */
    public boolean isVerified() {
        return preferences.getBoolean(KEY_IS_VERIFIED, false);
    }

    /**
     * Set verification status
     */
    public void setVerified(boolean verified) {
        preferences.edit().putBoolean(KEY_IS_VERIFIED, verified).apply();
    }

    /**
     * Get RSA private key
     */
    public String getPrivateKeyRSA() {
        return preferences.getString(KEY_PRIVATE_KEY_RSA, null);
    }

    /**
     * Set RSA private key
     */
    public void setPrivateKeyRSA(String key) {
        preferences.edit().putString(KEY_PRIVATE_KEY_RSA, key).apply();
    }

    /**
     * Get RSA public key
     */
    public String getPublicKeyRSA() {
        return preferences.getString(KEY_PUBLIC_KEY_RSA, null);
    }

    /**
     * Set RSA public key
     */
    public void setPublicKeyRSA(String key) {
        preferences.edit().putString(KEY_PUBLIC_KEY_RSA, key).apply();
    }

    /**
     * Get Ed25519 private key
     */
    public String getPrivateKeyEd25519() {
        return preferences.getString(KEY_PRIVATE_KEY_ED25519, null);
    }

    /**
     * Set Ed25519 private key
     */
    public void setPrivateKeyEd25519(String key) {
        preferences.edit().putString(KEY_PRIVATE_KEY_ED25519, key).apply();
    }

    /**
     * Get Ed25519 public key
     */
    public String getPublicKeyEd25519() {
        return preferences.getString(KEY_PUBLIC_KEY_ED25519, null);
    }

    /**
     * Set Ed25519 public key
     */
    public void setPublicKeyEd25519(String key) {
        preferences.edit().putString(KEY_PUBLIC_KEY_ED25519, key).apply();
    }

    /**
     * Get AES key
     */
    public String getAESKey() {
        return preferences.getString(KEY_AES_KEY, null);
    }

    /**
     * Set AES key
     */
    public void setAESKey(String key) {
        preferences.edit().putString(KEY_AES_KEY, key).apply();
    }

    /**
     * Get verification secret
     */
    public String getVerifySecret() {
        return preferences.getString(KEY_VERIFY_SECRET, null);
    }

    /**
     * Set verification secret
     */
    public void setVerifySecret(String secret) {
        preferences.edit().putString(KEY_VERIFY_SECRET, secret).apply();
    }

    /**
     * Clear cache but keep encryption keys
     */
    public void clearCache() {
        // This would typically clear message cache, media cache etc.
        // Keep encryption keys intact
        // Implementation depends on how cache is stored in your app
    }

    /**
     * Clear all encryption data (used during unregistration)
     */
    public void clearAll() {
        SharedPreferences.Editor editor = preferences.edit();
        editor.remove(KEY_USER_ID);
        editor.remove(KEY_IS_REGISTERED);
        editor.remove(KEY_IS_VERIFIED);
        editor.remove(KEY_PRIVATE_KEY_RSA);
        editor.remove(KEY_PUBLIC_KEY_RSA);
        editor.remove(KEY_PRIVATE_KEY_ED25519);
        editor.remove(KEY_PUBLIC_KEY_ED25519);
        editor.remove(KEY_AES_KEY);
        editor.remove(KEY_VERIFY_SECRET);
        editor.apply();
    }

    /**
     * Check if encryption is properly configured
     */
    public boolean isConfigured() {
        return getUserID() != -1 && getServerIP() != null && 
               !getServerIP().isEmpty() && getPublicKeyRSA() != null;
    }
}
