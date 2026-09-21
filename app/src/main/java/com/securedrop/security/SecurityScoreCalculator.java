package com.securedrop.security;

import android.content.Context;

import com.securedrop.data.pref.SecurityPreferences;

public class SecurityScoreCalculator {

    public static class ScoreResult {
        public final int totalScore; // 0 - 100
        public final boolean keystoreActive;
        public final boolean aesGcmActive;
        public final boolean sha256IntegrityActive;
        public final boolean screenshotProtectionActive;
        public final boolean biometricActive;
        public final boolean auditLoggingActive;
        public final boolean autoCleanupActive;

        public ScoreResult(int totalScore, boolean keystoreActive, boolean aesGcmActive,
                           boolean sha256IntegrityActive, boolean screenshotProtectionActive,
                           boolean biometricActive, boolean auditLoggingActive, boolean autoCleanupActive) {
            this.totalScore = totalScore;
            this.keystoreActive = keystoreActive;
            this.aesGcmActive = aesGcmActive;
            this.sha256IntegrityActive = sha256IntegrityActive;
            this.screenshotProtectionActive = screenshotProtectionActive;
            this.biometricActive = biometricActive;
            this.auditLoggingActive = auditLoggingActive;
            this.autoCleanupActive = autoCleanupActive;
        }
    }

    public static ScoreResult computeScore(Context context) {
        SecurityPreferences prefs = new SecurityPreferences(context);

        boolean keystore = true; // Always enforced in SecureDrop
        boolean aesGcm = true;   // Always enforced in SecureDrop
        boolean sha256 = true;   // Always enforced in SecureDrop
        boolean screenshot = prefs.isScreenshotProtectionEnabled();
        boolean biometric = prefs.isBiometricLockEnabled();
        boolean audit = true;    // Always active
        boolean cleanup = prefs.isAutoDeleteEnabled();

        int score = 0;
        if (aesGcm) score += 20;
        if (keystore) score += 15;
        if (sha256) score += 15;
        if (screenshot) score += 15;
        if (biometric) score += 15;
        if (audit) score += 10;
        if (cleanup) score += 10;

        return new ScoreResult(score, keystore, aesGcm, sha256, screenshot, biometric, audit, cleanup);
    }
}
