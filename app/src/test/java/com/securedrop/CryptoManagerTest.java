package com.securedrop;

import com.securedrop.crypto.CryptoManager;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Automated Unit Tests for SecureDrop Cryptographic Operations
 */
public class CryptoManagerTest {

    @Test
    public void testAesGcmEncryptionDecryption() throws Exception {
        String testMessage = "Confidential Financial Report 2026 - Q3 Balance Sheet";
        byte[] plaintext = testMessage.getBytes(StandardCharsets.UTF_8);

        // 1. Generate 256-bit AES key
        SecretKey key = CryptoManager.generateFileKey();
        assertNotNull(key);
        assertEquals(32, key.getEncoded().length); // 256 bits = 32 bytes

        // 2. Encrypt
        CryptoManager.EncryptedPayload payload = CryptoManager.encrypt(plaintext, key);
        assertNotNull(payload);
        assertNotNull(payload.ciphertext);
        assertNotNull(payload.iv);
        assertNotNull(payload.authTag);
        assertEquals(12, payload.iv.length); // 96-bit GCM IV
        assertEquals(16, payload.authTag.length); // 128-bit GCM Tag

        // Ensure ciphertext does not equal plaintext
        assertFalse(testMessage.equals(new String(payload.ciphertext, StandardCharsets.ISO_8859_1)));

        // 3. Decrypt
        byte[] decryptedBytes = CryptoManager.decrypt(payload.ciphertext, key, payload.iv);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        assertEquals(testMessage, decryptedMessage);
    }

    @Test
    public void testSha256IntegrityVerification() throws Exception {
        String data = "Verified Corporate Specification Document";
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);

        String hash1 = CryptoManager.computeSha256(bytes);
        assertNotNull(hash1);
        assertEquals(64, hash1.length()); // SHA-256 is 64 hex characters (256 bits)

        // Same data produces identical hash (Deterministic)
        String hash2 = CryptoManager.computeSha256(bytes);
        assertEquals(hash1, hash2);

        // Modified data produces distinct hash (Tamper detection)
        byte[] modified = data.replace("Verified", "Tampered").getBytes(StandardCharsets.UTF_8);
        String hash3 = CryptoManager.computeSha256(modified);
        assertFalse(hash1.equals(hash3));
    }

    @Test
    public void testTamperedCiphertextRejection() throws Exception {
        byte[] plaintext = "Highly sensitive payload".getBytes(StandardCharsets.UTF_8);
        SecretKey key = CryptoManager.generateFileKey();
        CryptoManager.EncryptedPayload payload = CryptoManager.encrypt(plaintext, key);

        // Tamper 1 bit in the ciphertext
        byte[] tampered = payload.ciphertext.clone();
        tampered[5] ^= 0x01;

        // SHA-256 must detect tampering
        String originalHash = payload.sha256Encrypted;
        String tamperedHash = CryptoManager.computeSha256(tampered);
        assertFalse(originalHash.equalsIgnoreCase(tamperedHash));

        // AES-GCM must throw AEADBadTagException on tampered data
        boolean exceptionThrown = false;
        try {
            CryptoManager.decrypt(tampered, key, payload.iv);
        } catch (AEADBadTagException e) {
            exceptionThrown = true;
        } catch (Exception e) {
            if (e.getCause() instanceof AEADBadTagException || (e.getMessage() != null && e.getMessage().contains("tag"))) {
                exceptionThrown = true;
            }
        }
        assertTrue("Expected AEADBadTagException on tampered ciphertext", exceptionThrown);
    }

    @Test
    public void testCompositeShareCodeParsing() throws Exception {
        SecretKey key = CryptoManager.generateFileKey();
        String token = "a1b2c3d4e5f60718293a4b5c6d7e8f90";

        String composite = CryptoManager.createCompositeShareCode(token, key);
        assertTrue(composite.startsWith(token + "#"));

        String[] parsed = CryptoManager.parseCompositeShareCode(composite);
        assertNotNull(parsed);
        assertEquals(2, parsed.length);
        assertEquals(token, parsed[0]);

        SecretKey recoveredKey = CryptoManager.decodeFileKey(parsed[1]);
        assertArrayEquals(key.getEncoded(), recoveredKey.getEncoded());

        // Test URL format
        String urlFormat = "https://securedrop.local/share/" + composite;
        String[] parsedFromUrl = CryptoManager.parseCompositeShareCode(urlFormat);
        assertEquals(token, parsedFromUrl[0]);
        assertEquals(parsed[1], parsedFromUrl[1]);
    }

    @Test
    public void testMemoryZeroization() {
        byte[] sensitiveBuffer = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        CryptoManager.wipeMemory(sensitiveBuffer);

        for (byte b : sensitiveBuffer) {
            assertEquals(0, b);
        }
    }
}
