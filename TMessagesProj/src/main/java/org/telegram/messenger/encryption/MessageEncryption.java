/*
 * Message encryption integration
 */

package org.telegram.messenger.encryption;

import android.content.Context;
import org.telegram.messenger.FileLog;

/**
 * Handles message encryption/decryption integration with the messaging system
 */
public class MessageEncryption {
    private EncryptionManager encryptionManager;
    private EncryptionSettings settings;

    public MessageEncryption(Context context) {
        this.encryptionManager = EncryptionManager.getInstance(context);
        this.settings = encryptionManager.getSettings();
    }

    /**
     * Process outgoing message - encrypt if recipient is registered
     */
    public ProcessedMessage processOutgoingMessage(String plaintext, long recipientId) {
        ProcessedMessage result = new ProcessedMessage();
        result.originalText = plaintext;
        result.recipientId = recipientId;
        result.isEncrypted = false;

        // Check if encryption is active
        if (!encryptionManager.isEncryptionActive()) {
            result.message = plaintext;
            result.status = "Not encrypted - encryption not configured";
            return result;
        }

        // Try to get recipient's public key
        encryptionManager.getRecipientPublicKey(recipientId, new EncryptionManager.EncryptionKeyCallback() {
            @Override
            public void onSuccess(String publicKey) {
                try {
                    EncryptionManager.EncryptedMessage encrypted = 
                        encryptionManager.encryptMessage(plaintext, publicKey);
                    
                    result.message = encrypted.content;
                    result.encryptedAesKey = encrypted.encryptedAesKey;
                    result.signature = encrypted.signature;
                    result.isEncrypted = encrypted.isEncrypted;
                    result.status = "✓ Encrypted";
                } catch (Exception e) {
                    FileLog.e(e);
                    result.message = plaintext;
                    result.status = "✗ Encryption failed: " + e.getMessage();
                }
            }

            @Override
            public void onError(String error) {
                FileLog.e("Encryption error: " + error);
                result.message = plaintext;
                result.status = "⚠ " + error + " - sending unencrypted";
            }
        });

        return result;
    }

    /**
     * Process incoming message - decrypt if encrypted
     */
    public ProcessedMessage processIncomingMessage(String receivedText, long senderId) {
        ProcessedMessage result = new ProcessedMessage();
        result.originalText = receivedText;
        result.senderId = senderId;

        // Check if message is encrypted
        if (receivedText == null) {
            result.message = "";
            result.status = "Empty message";
            return result;
        }

        if (!receivedText.startsWith("🔐 ")) {
            result.message = receivedText;
            result.isEncrypted = false;
            result.status = "Not encrypted";
            return result;
        }

        // Try to decrypt
        if (!encryptionManager.isEncryptionActive()) {
            result.message = receivedText;
            result.isEncrypted = true;
            result.status = "✗ Cannot decrypt - encryption not configured";
            return result;
        }

        try {
            EncryptionManager.DecryptedMessage decrypted = encryptionManager.decryptMessage(receivedText);
            result.message = decrypted.content;
            result.isEncrypted = decrypted.isEncrypted;
            result.status = decrypted.status;
            result.decryptionError = decrypted.error;
            return result;
        } catch (Exception e) {
            FileLog.e(e);
            result.message = receivedText;
            result.isEncrypted = true;
            result.status = "✗ Decryption failed";
            result.decryptionError = e.getMessage();
            return result;
        }
    }

    /**
     * Get display status for message
     */
    public String getMessageStatus(ProcessedMessage message) {
        if (message.isEncrypted) {
            return message.status;
        } else if ("Not encrypted".equals(message.status)) {
            return "Plain text";
        } else {
            return message.status;
        }
    }

    /**
     * Wrapper for processed messages
     */
    public static class ProcessedMessage {
        public String originalText;
        public String message;
        public long recipientId = -1;
        public long senderId = -1;
        public boolean isEncrypted;
        public String status;
        public String decryptionError;
        public String encryptedAesKey;
        public String signature;
    }
}
