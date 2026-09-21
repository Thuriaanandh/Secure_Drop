package com.securedrop.crypto;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Real Cryptographic Engine for SecureDrop:
 * - Client-side AES-256-GCM authenticated encryption and decryption
 * - SHA-256 cryptographic payload integrity verification
 * - Hardware/Android Keystore Master Key management and Key Wrapping
 * - Zero-knowledge key/token extraction
 */
public class CryptoManager {

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String MASTER_KEY_ALIAS = "SecureDropMasterStorageKey";
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE_BITS = 256;
    private static final int GCM_IV_LENGTH_BYTES = 12; // 96-bit standard GCM IV
    private static final int GCM_TAG_LENGTH_BITS = 128; // 128-bit authentication tag

    public static class EncryptedPayload {
        public final byte[] ciphertext;
        public final byte[] iv;
        public final byte[] authTag;
        public final String sha256Encrypted;
        public final String sha256Plaintext;
        public final SecretKey secretKey;

        public EncryptedPayload(byte[] ciphertext, byte[] iv, byte[] authTag, String sha256Encrypted, String sha256Plaintext, SecretKey secretKey) {
            this.ciphertext = ciphertext;
            this.iv = iv;
            this.authTag = authTag;
            this.sha256Encrypted = sha256Encrypted;
            this.sha256Plaintext = sha256Plaintext;
            this.secretKey = secretKey;
        }

        public String getIvHex() {
            return bytesToHex(iv);
        }

        public String getAuthTagHex() {
            return bytesToHex(authTag);
        }

        public String getKeyBase64Url() {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(secretKey.getEncoded());
        }
    }

    /**
     * Generates a cryptographically secure random 256-bit AES key
     */
    public static SecretKey generateFileKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(AES_KEY_SIZE_BITS, secureRandom);
        return keyGenerator.generateKey();
    }

    /**
     * Converts a base64url string to a SecretKey
     */
    public static SecretKey decodeFileKey(String base64UrlKey) {
        byte[] keyBytes = Base64.getUrlDecoder().decode(base64UrlKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Encrypts plaintext bytes using AES-256-GCM
     */
    public static EncryptedPayload encrypt(byte[] plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] cipherOutput = cipher.doFinal(plaintext);

        // In Java GCM, the 16-byte authentication tag is appended to the end of cipherOutput
        int ciphertextLen = cipherOutput.length - 16;
        byte[] ciphertextOnly = new byte[ciphertextLen];
        byte[] authTag = new byte[16];
        System.arraycopy(cipherOutput, 0, ciphertextOnly, 0, ciphertextLen);
        System.arraycopy(cipherOutput, ciphertextLen, authTag, 0, 16);

        String sha256Encrypted = computeSha256(cipherOutput);
        String sha256Plaintext = computeSha256(plaintext);

        return new EncryptedPayload(cipherOutput, iv, authTag, sha256Encrypted, sha256Plaintext, key);
    }

    /**
     * Decrypts encrypted payload using AES-256-GCM.
     * Note: cipherOutput contains ciphertext + 16-byte GCM tag.
     */
    public static byte[] decrypt(byte[] cipherOutput, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(cipherOutput);
    }

    /**
     * Computes SHA-256 hash string (lowercase hex) of byte array
     */
    public static String computeSha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Computes SHA-256 hash string (lowercase hex) of InputStream
     */
    public static String computeSha256(InputStream inputStream) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192];
        int read;
        while ((read = inputStream.read(buffer)) != -1) {
            digest.update(buffer, 0, read);
        }
        return bytesToHex(digest.digest());
    }

    /**
     * Android Keystore Master Key initialisation:
     * Generates a 256-bit AES master key inside AndroidKeyStore if not already present.
     */
    public static synchronized void ensureKeystoreMasterKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            if (!keyStore.containsAlias(MASTER_KEY_ALIAS)) {
                KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                        MASTER_KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(AES_KEY_SIZE_BITS)
                        .setRandomizedEncryptionRequired(true)
                        .build();
                keyGen.init(spec);
                keyGen.generateKey();
            }
        } catch (Exception e) {
            // In unit tests or environments where AndroidKeyStore is mocked or unavailable, log warning
            System.err.println("[Keystore] Note: " + e.getMessage());
        }
    }

    /**
     * Wraps a file encryption key using the Android Keystore Master Key.
     * Returns: [12-byte IV][Ciphertext of wrapped key] as Base64 string.
     */
    public static String wrapKeyWithKeystore(SecretKey fileKey) throws Exception {
        ensureKeystoreMasterKey();
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        SecretKey masterKey = (SecretKey) keyStore.getKey(MASTER_KEY_ALIAS, null);

        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey);
        byte[] iv = cipher.getIV();
        byte[] encryptedKeyBytes = cipher.doFinal(fileKey.getEncoded());

        byte[] combined = new byte[iv.length + encryptedKeyBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedKeyBytes, 0, combined, iv.length, encryptedKeyBytes.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Unwraps a file encryption key using the Android Keystore Master Key.
     */
    public static SecretKey unwrapKeyWithKeystore(String wrappedKeyBase64) throws Exception {
        ensureKeystoreMasterKey();
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        SecretKey masterKey = (SecretKey) keyStore.getKey(MASTER_KEY_ALIAS, null);

        byte[] combined = Base64.getDecoder().decode(wrappedKeyBase64);
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        byte[] encryptedKeyBytes = new byte[combined.length - GCM_IV_LENGTH_BYTES];
        System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH_BYTES);
        System.arraycopy(combined, GCM_IV_LENGTH_BYTES, encryptedKeyBytes, 0, encryptedKeyBytes.length);

        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, masterKey, spec);

        byte[] rawKey = cipher.doFinal(encryptedKeyBytes);
        return new SecretKeySpec(rawKey, "AES");
    }

    /**
     * Creates an end-to-end composite share link/code:
     * Format: SECUREDROP-SHARE-{TOKEN}#{KEY_BASE64URL}
     */
    public static String createCompositeShareCode(String token, SecretKey key) {
        String keyB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(key.getEncoded());
        return token + "#" + keyB64;
    }

    /**
     * Parses a composite share code into [token, keyBase64Url]
     */
    public static String[] parseCompositeShareCode(String compositeCode) {
        if (compositeCode == null) return null;
        String clean = compositeCode.trim();
        // If it's a full URL like https://securedrop.local/share/<token>#<key>
        if (clean.contains("/share/")) {
            int idx = clean.indexOf("/share/");
            clean = clean.substring(idx + 7);
        }
        if (clean.contains("#")) {
            return clean.split("#", 2);
        }
        // Fallback: token only
        return new String[]{clean, ""};
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Securely zeroizes sensitive memory buffers
     */
    public static void wipeMemory(byte[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, (byte) 0);
        }
    }
}
