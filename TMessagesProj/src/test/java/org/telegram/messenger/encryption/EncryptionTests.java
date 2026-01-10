/*
 * Unit tests for encryption module
 */

package org.telegram.messenger.encryption;

import android.content.Context;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

/**
 * Tests for cryptographic utilities and encryption operations
 */
@RunWith(AndroidJUnit4.class)
public class EncryptionTests {
    private Context context;
    private EncryptionSettings settings;
    private String testPlaintext = "Hello, World! This is a test message.";

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        settings = new EncryptionSettings(context);
        // Clear previous test data
        settings.clearAll();
    }

    /**
     * Test AES key generation
     */
    @Test
    public void testAESKeyGeneration() throws Exception {
        SecretKey key = CryptoUtils.generateAESKey();
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length); // 256 bits = 32 bytes
    }

    /**
     * Test RSA key pair generation
     */
    @Test
    public void testRSAKeyGeneration() throws Exception {
        KeyPair keyPair = CryptoUtils.generateRSAKeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
        assertEquals("RSA", keyPair.getPrivate().getAlgorithm());
        assertEquals("RSA", keyPair.getPublic().getAlgorithm());
    }

    /**
     * Test AES encryption and decryption
     */
    @Test
    public void testAESEncryptionDecryption() throws Exception {
        SecretKey key = CryptoUtils.generateAESKey();
        
        // Encrypt
        String encrypted = CryptoUtils.encryptAES(testPlaintext, key);
        assertNotNull(encrypted);
        assertNotEquals(testPlaintext, encrypted);
        assertTrue(encrypted.length() > 0);

        // Decrypt
        String decrypted = CryptoUtils.decryptAES(encrypted, key);
        assertEquals(testPlaintext, decrypted);
    }

    /**
     * Test AES encryption randomness
     */
    @Test
    public void testAESEncryptionRandomness() throws Exception {
        SecretKey key = CryptoUtils.generateAESKey();
        
        String encrypted1 = CryptoUtils.encryptAES(testPlaintext, key);
        String encrypted2 = CryptoUtils.encryptAES(testPlaintext, key);
        
        // Same plaintext should produce different ciphertexts (due to random IV)
        assertNotEquals(encrypted1, encrypted2);
        
        // Both should decrypt to the same plaintext
        String decrypted1 = CryptoUtils.decryptAES(encrypted1, key);
        String decrypted2 = CryptoUtils.decryptAES(encrypted2, key);
        assertEquals(decrypted1, decrypted2);
        assertEquals(testPlaintext, decrypted1);
    }

    /**
     * Test RSA encryption and decryption
     */
    @Test
    public void testRSAEncryptionDecryption() throws Exception {
        KeyPair keyPair = CryptoUtils.generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // Encrypt with public key
        String encrypted = CryptoUtils.encryptRSA(testPlaintext, publicKey);
        assertNotNull(encrypted);
        assertNotEquals(testPlaintext, encrypted);

        // Decrypt with private key
        String decrypted = CryptoUtils.decryptRSA(encrypted, privateKey);
        assertEquals(testPlaintext, decrypted);
    }

    /**
     * Test public key encoding and decoding
     */
    @Test
    public void testPublicKeyEncodingDecoding() throws Exception {
        KeyPair keyPair = CryptoUtils.generateRSAKeyPair();
        PublicKey originalKey = keyPair.getPublic();
        
        // Encode
        String encoded = CryptoUtils.encodePublicKey(originalKey);
        assertNotNull(encoded);
        assertTrue(encoded.length() > 0);

        // Decode
        PublicKey decodedKey = CryptoUtils.decodePublicKey(encoded);
        assertNotNull(decodedKey);
        assertEquals(originalKey, decodedKey);
    }

    /**
     * Test secret key encoding and decoding
     */
    @Test
    public void testSecretKeyEncodingDecoding() throws Exception {
        SecretKey originalKey = CryptoUtils.generateAESKey();
        
        // Encode
        String encoded = CryptoUtils.encodeSecretKey(originalKey);
        assertNotNull(encoded);

        // Decode
        SecretKey decodedKey = CryptoUtils.decodeSecretKey(encoded);
        assertNotNull(decodedKey);
        assertArrayEquals(originalKey.getEncoded(), decodedKey.getEncoded());
    }

    /**
     * Test message signing
     */
    @Test
    public void testMessageSigning() throws Exception {
        KeyPair keyPair = CryptoUtils.generateRSAKeyPair();
        
        String signature = CryptoUtils.signMessage(testPlaintext, keyPair.getPrivate());
        assertNotNull(signature);
        assertTrue(signature.length() > 0);

        // Verify signature
        boolean verified = CryptoUtils.verifySignature(testPlaintext, signature, keyPair.getPublic());
        assertTrue(verified);
        
        // Verify with wrong message fails
        boolean wrongVerified = CryptoUtils.verifySignature("Wrong message", signature, keyPair.getPublic());
        assertFalse(wrongVerified);
    }

    /**
     * Test encryption settings storage
     */
    @Test
    public void testEncryptionSettingsStorage() {
        // Test server IP
        settings.setServerIP("192.168.1.100:8000");
        assertEquals("192.168.1.100:8000", settings.getServerIP());

        // Test user ID
        settings.setUserID(12345);
        assertEquals(12345, settings.getUserID());

        // Test registration status
        settings.setRegistered(true);
        assertTrue(settings.isRegistered());
        settings.setRegistered(false);
        assertFalse(settings.isRegistered());

        // Test verification status
        settings.setVerified(true);
        assertTrue(settings.isVerified());
    }

    /**
     * Test keys storage
     */
    @Test
    public void testKeysStorage() throws Exception {
        KeyPair rsaKeyPair = CryptoUtils.generateRSAKeyPair();
        KeyPair ed25519KeyPair = CryptoUtils.generateEd25519KeyPair();
        SecretKey aesKey = CryptoUtils.generateAESKey();

        String publicKeyRSA = CryptoUtils.encodePublicKey(rsaKeyPair.getPublic());
        String publicKeyEd25519 = CryptoUtils.encodePublicKey(ed25519KeyPair.getPublic());
        String aesKeyStr = CryptoUtils.encodeSecretKey(aesKey);

        // Store
        settings.setPublicKeyRSA(publicKeyRSA);
        settings.setPublicKeyEd25519(publicKeyEd25519);
        settings.setAESKey(aesKeyStr);

        // Retrieve
        assertEquals(publicKeyRSA, settings.getPublicKeyRSA());
        assertEquals(publicKeyEd25519, settings.getPublicKeyEd25519());
        assertEquals(aesKeyStr, settings.getAESKey());
    }

    /**
     * Test configuration check
     */
    @Test
    public void testConfigurationCheck() {
        // Not configured
        assertFalse(settings.isConfigured());

        // Partial configuration
        settings.setServerIP("192.168.1.100");
        assertFalse(settings.isConfigured());

        settings.setUserID(12345);
        assertFalse(settings.isConfigured());

        // Fully configured
        try {
            KeyPair keyPair = CryptoUtils.generateRSAKeyPair();
            settings.setPublicKeyRSA(CryptoUtils.encodePublicKey(keyPair.getPublic()));
            assertTrue(settings.isConfigured());
        } catch (Exception e) {
            fail("Exception: " + e.getMessage());
        }
    }

    /**
     * Test message encryption wrapper
     */
    @Test
    public void testEncryptionManager() {
        EncryptionManager manager = EncryptionManager.getInstance(context);
        assertNotNull(manager);
        assertFalse(manager.isEncryptionActive());
        
        // After registration
        settings.setRegistered(true);
        assertFalse(manager.isEncryptionActive()); // Still needs verification
        
        // After verification
        settings.setVerified(true);
        assertTrue(manager.isEncryptionActive());
    }

    /**
     * Test message processing
     */
    @Test
    public void testMessageProcessing() {
        MessageEncryption messageEncryption = new MessageEncryption(context);
        
        // Unencrypted message
        MessageEncryption.ProcessedMessage processed = 
            messageEncryption.processIncomingMessage("Hello", 12345);
        
        assertNotNull(processed);
        assertEquals("Hello", processed.message);
        assertFalse(processed.isEncrypted);
        assertEquals("Not encrypted", processed.status);
    }

    /**
     * Test encryption status view
     */
    @Test
    public void testEncryptionStatusView() {
        // This would require Android test framework setup
        // Placeholder for now
    }
}
