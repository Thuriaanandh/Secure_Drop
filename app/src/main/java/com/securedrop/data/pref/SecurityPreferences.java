package com.securedrop.data.pref;

import android.content.Context;
import android.content.SharedPreferences;

public class SecurityPreferences {

    private static final String PREF_NAME = "securedrop_security_prefs";

    // Keys
    private static final String KEY_SERVER_URL = "server_url";
    private static final String KEY_AUTH_TOKEN = "auth_token";
    private static final String KEY_USER_ID = "user_id";
    private static final String KEY_USERNAME = "username";
    private static final String KEY_USER_EMAIL = "user_email";
    private static final String KEY_BIOMETRIC_LOCK = "biometric_lock_enabled";
    private static final String KEY_SCREENSHOT_PROTECTION = "screenshot_protection_enabled";
    private static final String KEY_AUTO_DELETE = "auto_delete_enabled";
    private static final String KEY_REQUIRE_AUTH_DOWNLOAD = "require_auth_download";
    private static final String KEY_TEST_MODE = "test_mode_enabled";
    private static final String KEY_APP_LOCKED = "app_locked";

    // Default development server URL: 10.0.2.2 connects from Android emulator to host machine!
    public static final String DEFAULT_SERVER_URL = "http://10.0.2.2:3000";

    private final SharedPreferences prefs;

    public SecurityPreferences(Context context) {
        this.prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
    }

    public String getServerUrl() {
        return prefs.getString(KEY_SERVER_URL, DEFAULT_SERVER_URL);
    }

    public void setServerUrl(String url) {
        prefs.edit().putString(KEY_SERVER_URL, url).apply();
    }

    public String getAuthToken() {
        return prefs.getString(KEY_AUTH_TOKEN, null);
    }

    public void setAuthToken(String token) {
        prefs.edit().putString(KEY_AUTH_TOKEN, token).apply();
    }

    public boolean isLoggedIn() {
        return getAuthToken() != null && !getAuthToken().trim().isEmpty();
    }

    public void saveUserSession(String token, String userId, String username, String email) {
        prefs.edit()
                .putString(KEY_AUTH_TOKEN, token)
                .putString(KEY_USER_ID, userId)
                .putString(KEY_USERNAME, username)
                .putString(KEY_USER_EMAIL, email)
                .apply();
    }

    public void clearUserSession() {
        prefs.edit()
                .remove(KEY_AUTH_TOKEN)
                .remove(KEY_USER_ID)
                .remove(KEY_USERNAME)
                .remove(KEY_USER_EMAIL)
                .apply();
    }

    public String getUserId() {
        return prefs.getString(KEY_USER_ID, "");
    }

    public String getUsername() {
        return prefs.getString(KEY_USERNAME, "Security User");
    }

    public String getUserEmail() {
        return prefs.getString(KEY_USER_EMAIL, "");
    }

    public boolean isBiometricLockEnabled() {
        return prefs.getBoolean(KEY_BIOMETRIC_LOCK, false);
    }

    public void setBiometricLockEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_BIOMETRIC_LOCK, enabled).apply();
    }

    public boolean isScreenshotProtectionEnabled() {
        return prefs.getBoolean(KEY_SCREENSHOT_PROTECTION, true); // Default ON
    }

    public void setScreenshotProtectionEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_SCREENSHOT_PROTECTION, enabled).apply();
    }

    public boolean isAutoDeleteEnabled() {
        return prefs.getBoolean(KEY_AUTO_DELETE, true); // Default ON
    }

    public void setAutoDeleteEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_AUTO_DELETE, enabled).apply();
    }

    public boolean isRequireAuthDownload() {
        return prefs.getBoolean(KEY_REQUIRE_AUTH_DOWNLOAD, true); // Default ON
    }

    public void setRequireAuthDownload(boolean enabled) {
        prefs.edit().putBoolean(KEY_REQUIRE_AUTH_DOWNLOAD, enabled).apply();
    }

    public boolean isTestModeEnabled() {
        return prefs.getBoolean(KEY_TEST_MODE, false);
    }

    public void setTestModeEnabled(boolean enabled) {
        prefs.edit().putBoolean(KEY_TEST_MODE, enabled).apply();
    }

    public boolean isAppLocked() {
        return prefs.getBoolean(KEY_APP_LOCKED, false);
    }

    public void setAppLocked(boolean locked) {
        prefs.edit().putBoolean(KEY_APP_LOCKED, locked).apply();
    }
}
