package com.securedrop.ui.base;

import android.content.Intent;
import android.os.Bundle;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.securedrop.data.pref.SecurityPreferences;
import com.securedrop.security.AuditLogger;
import com.securedrop.security.ScreenshotProtectionHelper;
import com.securedrop.ui.auth.BiometricLockActivity;

public abstract class BaseActivity extends AppCompatActivity {

    protected SecurityPreferences securityPrefs;
    private final ScreenshotProtectionHelper screenshotHelper = new ScreenshotProtectionHelper();
    private static long lastBackgroundTimestamp = 0;
    private static boolean isAppInBackground = false;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        securityPrefs = new SecurityPreferences(this);
    }

    @Override
    protected void onResume() {
        super.onResume();
        // 1. Enforce Window FLAG_SECURE & Android 14 screenshot callbacks
        boolean screenshotProtection = securityPrefs.isScreenshotProtectionEnabled();
        screenshotHelper.applyProtection(this, screenshotProtection, () -> {
            AuditLogger.logEvent(
                    BaseActivity.this,
                    "SCREENSHOT_DETECTED",
                    "WARNING",
                    "Screenshot attempted while viewing " + getClass().getSimpleName(),
                    null
            );
        });

        // 2. Biometric App Lock Check on return from background
        if (securityPrefs.isLoggedIn() && securityPrefs.isBiometricLockEnabled()) {
            if (isAppInBackground && System.currentTimeMillis() - lastBackgroundTimestamp > 15000) { // 15 seconds grace
                isAppInBackground = false;
                if (!getClass().getSimpleName().equals("BiometricLockActivity")) {
                    Intent lockIntent = new Intent(this, BiometricLockActivity.class);
                    startActivity(lockIntent);
                }
            }
        }
        isAppInBackground = false;
    }

    @Override
    protected void onPause() {
        super.onPause();
        lastBackgroundTimestamp = System.currentTimeMillis();
        isAppInBackground = true;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        screenshotHelper.removeCallback(this);
    }
}
