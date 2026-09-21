package com.securedrop.ui.security;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import com.securedrop.R;
import com.securedrop.ui.base.BaseActivity;

public class SecurityDemoActivity extends BaseActivity {

    private static class TestListItemHolder {
        View card;
        TextView tvTitle, tvExpected, tvBadge, tvActual;

        TestListItemHolder(View view, String title, String expected, int testId, SecurityDemoActivity activity) {
            card = view;
            tvTitle = view.findViewById(R.id.tvTestTitle);
            tvExpected = view.findViewById(R.id.tvExpectedResult);
            tvBadge = view.findViewById(R.id.tvTestBadge);
            tvActual = view.findViewById(R.id.tvActualResult);

            tvTitle.setText(title);
            tvExpected.setText(expected);
            tvActual.setText("Tap to open test window");
            tvBadge.setText("READY");

            // Clicking opens the dedicated SecurityTestRunnerActivity window
            card.setOnClickListener(v -> {
                Intent intent = new Intent(activity, SecurityTestRunnerActivity.class);
                intent.putExtra("test_id", testId);
                activity.startActivity(intent);
            });
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_security_demo);

        findViewById(R.id.btnBack).setOnClickListener(v -> finish());

        new TestListItemHolder(findViewById(R.id.cardTestEncryption),
                "TEST 1: Client-Side AES-256-GCM Encryption",
                "Ciphertext != Plaintext, 12B IV, 16B GCM tag, exact decrypted plaintext",
                1, this);

        new TestListItemHolder(findViewById(R.id.cardTestIntegrity),
                "TEST 2: Cryptographic Tamper & Integrity Rejection",
                "Tampered ciphertext fails SHA-256 check and throws AEADBadTagException",
                2, this);

        new TestListItemHolder(findViewById(R.id.cardTestExpiringLink),
                "TEST 3: Expiring Link Rejection (1-Second Expiry)",
                "Server enforces expiry timestamp; returns HTTP 410 Gone / Expired",
                3, this);

        new TestListItemHolder(findViewById(R.id.cardTestOneTime),
                "TEST 4: One-Time Download Enforcement (\"Burn on Read\")",
                "1st download succeeds (200 OK); 2nd download permanently blocked (HTTP 410)",
                4, this);

        new TestListItemHolder(findViewById(R.id.cardTestRevocation),
                "TEST 5: Instant Share Revocation (Kill Switch)",
                "Sender revokes share; recipient is immediately blocked (HTTP 403 Access Revoked)",
                5, this);

        new TestListItemHolder(findViewById(R.id.cardTestScreenshot),
                "TEST 6: Screenshot Protection (FLAG_SECURE)",
                "Window attributes contain FLAG_SECURE; screenshots and screen recording blocked",
                6, this);

        new TestListItemHolder(findViewById(R.id.cardTestBiometric),
                "TEST 7: Biometric Authentication Gate",
                "BiometricManager & hardware TEE / StrongBox key protection operational",
                7, this);

        new TestListItemHolder(findViewById(R.id.cardTestIdor),
                "TEST 8: IDOR Object-Level Authorization Defense",
                "Attacker querying another user's fileId receives HTTP 403 Forbidden",
                8, this);
    }
}
