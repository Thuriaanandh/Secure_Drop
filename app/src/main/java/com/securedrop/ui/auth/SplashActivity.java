package com.securedrop.ui.auth;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;

import androidx.appcompat.app.AppCompatActivity;

import com.securedrop.R;
import com.securedrop.crypto.CryptoManager;
import com.securedrop.data.pref.SecurityPreferences;
import com.securedrop.ui.main.MainActivity;

public class SplashActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_splash);

        // Ensure Keystore hardware/software master key is initialized
        new Thread(CryptoManager::ensureKeystoreMasterKey).start();

        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            SecurityPreferences prefs = new SecurityPreferences(this);
            if (!prefs.isLoggedIn()) {
                Intent intent = new Intent(SplashActivity.this, OnboardingActivity.class);
                startActivity(intent);
            } else if (prefs.isBiometricLockEnabled()) {
                Intent intent = new Intent(SplashActivity.this, BiometricLockActivity.class);
                startActivity(intent);
            } else {
                Intent intent = new Intent(SplashActivity.this, MainActivity.class);
                startActivity(intent);
            }
            finish();
        }, 1200);
    }
}
