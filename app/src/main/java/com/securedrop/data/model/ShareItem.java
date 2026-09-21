package com.securedrop.data.model;

public class ShareItem {
    public final String id;
    public final String fileId;
    public final String token;
    public final String compositeCode;
    public final long expiresAt;
    public final boolean oneTime;
    public final int downloadCount;
    public final boolean revoked;
    public final boolean hasPasscode;
    public final boolean requireBiometric;
    public final boolean preventScreenshots;
    public final long createdAt;
    public String filename;

    public ShareItem(String id, String fileId, String token, String compositeCode,
                     long expiresAt, boolean oneTime, int downloadCount, boolean revoked,
                     boolean hasPasscode, boolean requireBiometric, boolean preventScreenshots,
                     long createdAt, String filename) {
        this.id = id;
        this.fileId = fileId;
        this.token = token;
        this.compositeCode = compositeCode;
        this.expiresAt = expiresAt;
        this.oneTime = oneTime;
        this.downloadCount = downloadCount;
        this.revoked = revoked;
        this.hasPasscode = hasPasscode;
        this.requireBiometric = requireBiometric;
        this.preventScreenshots = preventScreenshots;
        this.createdAt = createdAt;
        this.filename = filename;
    }

    public boolean isExpired() {
        return System.currentTimeMillis() > expiresAt;
    }

    public boolean isConsumed() {
        return oneTime && downloadCount >= 1;
    }

    public String getStatusDescription() {
        if (revoked) return "Revoked";
        if (isExpired()) return "Expired";
        if (isConsumed()) return "Consumed (1-time)";
        return "Active";
    }
}
