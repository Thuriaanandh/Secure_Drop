package com.securedrop.ui.security;

import android.content.Intent;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.Toast;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.switchmaterial.SwitchMaterial;
import com.securedrop.R;
import com.securedrop.ui.auth.AuthActivity;
import com.securedrop.ui.base.BaseActivity;

public class SettingsActivity extends BaseActivity {

    private SwitchMaterial switchBiometricLock, switchScreenshotProtection, switchAutoDelete, switchRequireAuthDownload, switchTestMode;
    private EditText etServerUrlSettings;
    private MaterialButton btnSaveServerUrl, btnLogout;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        switchBiometricLock = findViewById(R.id.switchBiometricLock);
        switchScreenshotProtection = findViewById(R.id.switchScreenshotProtection);
        switchAutoDelete = findViewById(R.id.switchAutoDelete);
        switchRequireAuthDownload = findViewById(R.id.switchRequireAuthDownload);
        switchTestMode = findViewById(R.id.switchTestMode);
        etServerUrlSettings = findViewById(R.id.etServerUrlSettings);
        btnSaveServerUrl = findViewById(R.id.btnSaveServerUrl);
        btnLogout = findViewById(R.id.btnLogout);

        findViewById(R.id.btnBack).setOnClickListener(v -> finish());

        // Load current prefs
        switchBiometricLock.setChecked(securityPrefs.isBiometricLockEnabled());
        switchScreenshotProtection.setChecked(securityPrefs.isScreenshotProtectionEnabled());
        switchAutoDelete.setChecked(securityPrefs.isAutoDeleteEnabled());
        switchRequireAuthDownload.setChecked(securityPrefs.isRequireAuthDownload());
        switchTestMode.setChecked(securityPrefs.isTestModeEnabled());
        etServerUrlSettings.setText(securityPrefs.getServerUrl());

        // Listeners
        switchBiometricLock.setOnCheckedChangeListener((buttonView, isChecked) -> securityPrefs.setBiometricLockEnabled(isChecked));
        switchScreenshotProtection.setOnCheckedChangeListener((buttonView, isChecked) -> securityPrefs.setScreenshotProtectionEnabled(isChecked));
        switchAutoDelete.setOnCheckedChangeListener((buttonView, isChecked) -> securityPrefs.setAutoDeleteEnabled(isChecked));
        switchRequireAuthDownload.setOnCheckedChangeListener((buttonView, isChecked) -> securityPrefs.setRequireAuthDownload(isChecked));
        switchTestMode.setOnCheckedChangeListener((buttonView, isChecked) -> securityPrefs.setTestModeEnabled(isChecked));

        btnSaveServerUrl.setOnClickListener(v -> {
            String newUrl = etServerUrlSettings.getText().toString().trim();
            if (!newUrl.isEmpty()) {
                securityPrefs.setServerUrl(newUrl);
                Toast.makeText(this, "Backend server URL saved", Toast.LENGTH_SHORT).show();
            }
        });

        btnLogout.setOnClickListener(v -> {
            securityPrefs.clearUserSession();
            Intent intent = new Intent(this, AuthActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
        });
    }
}
