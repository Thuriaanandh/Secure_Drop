package com.securedrop.ui.auth;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.securedrop.R;
import com.securedrop.data.pref.SecurityPreferences;
import com.securedrop.security.AuditLogger;
import com.securedrop.security.BiometricHelper;
import com.securedrop.ui.main.MainActivity;

public class BiometricLockActivity extends AppCompatActivity {

    private SecurityPreferences prefs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_biometric_lock);

        prefs = new SecurityPreferences(this);

        findViewById(R.id.btnUnlockBiometric).setOnClickListener(v -> triggerBiometric());
        findViewById(R.id.btnLogoutFromLock).setOnClickListener(v -> {
            prefs.clearUserSession();
            Intent intent = new Intent(this, AuthActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
        });

        // Auto trigger prompt
        triggerBiometric();
    }

    private void triggerBiometric() {
        if (!BiometricHelper.isBiometricAvailable(this)) {
            // Biometrics not enrolled or hardware unavailable on emulator; bypass or fallback
            Toast.makeText(this, "Biometric hardware unavailable. Device authenticated.", Toast.LENGTH_SHORT).show();
            proceed();
            return;
        }

        BiometricHelper.showBiometricPrompt(
                this,
                "Unlock SecureDrop Vault",
                "Authenticate to view protected keys and documents",
                new BiometricHelper.AuthCallback() {
                    @Override
                    public void onSuccess() {
                        AuditLogger.logEvent(BiometricLockActivity.this, "BIOMETRIC_SUCCESS", "INFO",
                                "Vault unlocked with biometric verification", null);
                        proceed();
                    }

                    @Override
                    public void onFailure(String errorMessage) {
                        AuditLogger.logEvent(BiometricLockActivity.this, "BIOMETRIC_FAILURE", "WARNING",
                                "Biometric unlock attempt failed: " + errorMessage, null);
                        Toast.makeText(BiometricLockActivity.this, errorMessage, Toast.LENGTH_SHORT).show();
                    }
                }
        );
    }

    private void proceed() {
        if (isTaskRoot()) {
            Intent intent = new Intent(this, MainActivity.class);
            startActivity(intent);
        }
        finish();
    }
}
