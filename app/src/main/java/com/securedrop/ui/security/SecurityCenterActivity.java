package com.securedrop.ui.security;

import android.os.Bundle;
import android.widget.TextView;

import com.securedrop.R;
import com.securedrop.security.SecurityScoreCalculator;
import com.securedrop.ui.base.BaseActivity;

public class SecurityCenterActivity extends BaseActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_security_center);

        findViewById(R.id.btnBack).setOnClickListener(v -> finish());

        TextView tvSecurityCenterScore = findViewById(R.id.tvSecurityCenterScore);
        TextView badgeScreenshot = findViewById(R.id.badgeScreenshot);
        TextView badgeBiometric = findViewById(R.id.badgeBiometric);

        SecurityScoreCalculator.ScoreResult scoreResult = SecurityScoreCalculator.computeScore(this);
        tvSecurityCenterScore.setText(scoreResult.totalScore + " / 100");

        if (scoreResult.screenshotProtectionActive) {
            badgeScreenshot.setText("✓ FLAG_SECURE (+15)");
            badgeScreenshot.setBackgroundResource(R.drawable.bg_badge_green);
            badgeScreenshot.setTextColor(getColor(R.color.security_green));
        } else {
            badgeScreenshot.setText("Disabled (0)");
            badgeScreenshot.setBackgroundResource(R.drawable.bg_badge_amber);
            badgeScreenshot.setTextColor(getColor(R.color.security_amber));
        }

        if (scoreResult.biometricActive) {
            badgeBiometric.setText("✓ Biometrics (+15)");
            badgeBiometric.setBackgroundResource(R.drawable.bg_badge_green);
            badgeBiometric.setTextColor(getColor(R.color.security_green));
        } else {
            badgeBiometric.setText("Disabled (0)");
            badgeBiometric.setBackgroundResource(R.drawable.bg_badge_amber);
            badgeBiometric.setTextColor(getColor(R.color.security_amber));
        }
    }
}
