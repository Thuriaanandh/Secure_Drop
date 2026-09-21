package com.securedrop.data.model;

public class FileItem {
    public final String id;
    public final String originalName;
    public final String mimeType;
    public final long encryptedSize;
    public final long plaintextSize;
    public final String sha256Hash;
    public final String plaintextSha256;
    public final String ivHex;
    public final String authTagHex;
    public final long createdAt;
    public String wrappedKey; // Keystore wrapped key for owner decryption

    public FileItem(String id, String originalName, String mimeType, long encryptedSize,
                    long plaintextSize, String sha256Hash, String plaintextSha256,
                    String ivHex, String authTagHex, long createdAt) {
        this.id = id;
        this.originalName = originalName;
        this.mimeType = mimeType;
        this.encryptedSize = encryptedSize;
        this.plaintextSize = plaintextSize;
        this.sha256Hash = sha256Hash;
        this.plaintextSha256 = plaintextSha256;
        this.ivHex = ivHex;
        this.authTagHex = authTagHex;
        this.createdAt = createdAt;
    }

    public String getFormattedSize() {
        if (encryptedSize < 1024) return encryptedSize + " B";
        if (encryptedSize < 1024 * 1024) return String.format("%.1f KB", encryptedSize / 1024.0);
        return String.format("%.2f MB", encryptedSize / (1024.0 * 1024.0));
    }
}
