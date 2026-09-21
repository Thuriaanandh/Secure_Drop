package com.securedrop.ui.auth;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import com.securedrop.R;

public class OnboardingActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_onboarding);

        findViewById(R.id.btnGetStarted).setOnClickListener(v -> {
            Intent intent = new Intent(OnboardingActivity.this, AuthActivity.class);
            startActivity(intent);
            finish();
        });
    }
}
