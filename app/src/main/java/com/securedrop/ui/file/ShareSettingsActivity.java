package com.securedrop.ui.file;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.switchmaterial.SwitchMaterial;
import com.securedrop.R;
import com.securedrop.crypto.CryptoManager;
import com.securedrop.data.db.SecureDropDatabaseHelper;
import com.securedrop.data.model.FileItem;
import com.securedrop.data.model.ShareItem;
import com.securedrop.network.ApiClient;
import com.securedrop.security.AuditLogger;
import com.securedrop.ui.base.BaseActivity;

import org.json.JSONObject;

import javax.crypto.SecretKey;

public class ShareSettingsActivity extends BaseActivity {

    private String fileId;
    private String fileName;
    private String rawFileKeyBase64;

    private TextView tvTargetFileName, tvShareError;
    private Spinner spinnerExpiration;
    private SwitchMaterial switchOneTime, switchPasscode, switchRequireBiometric;
    private EditText etPasscode;
    private ProgressBar pbCreatingShare;
    private MaterialButton btnCreateSecureShare;

    private static final String[] EXPIRATION_LABELS = {
            "24 Hours (Recommended)",
            "30 Seconds (Test/Demo Mode)",
            "1 Minute (Test/Demo Mode)",
            "5 Minutes (Test/Demo Mode)",
            "10 Minutes",
            "1 Hour",
            "6 Hours",
            "7 Days"
    };

    private static final long[] EXPIRATION_SECONDS = {
            86400, // 24h
            30,    // 30s
            60,    // 1m
            300,   // 5m
            600,   // 10m
            3600,  // 1h
            21600, // 6h
            604800 // 7d
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_share_settings);

        fileId = getIntent().getStringExtra("file_id");
        fileName = getIntent().getStringExtra("file_name");
        rawFileKeyBase64 = getIntent().getStringExtra("raw_file_key");

        if (fileId == null) {
            finish();
            return;
        }

        tvTargetFileName = findViewById(R.id.tvTargetFileName);
        tvShareError = findViewById(R.id.tvShareError);
        spinnerExpiration = findViewById(R.id.spinnerExpiration);
        switchOneTime = findViewById(R.id.switchOneTime);
        switchPasscode = findViewById(R.id.switchPasscode);
        switchRequireBiometric = findViewById(R.id.switchRequireBiometric);
        etPasscode = findViewById(R.id.etPasscode);
        pbCreatingShare = findViewById(R.id.pbCreatingShare);
        btnCreateSecureShare = findViewById(R.id.btnCreateSecureShare);

        tvTargetFileName.setText("Target Document: " + (fileName != null ? fileName : fileId));
        findViewById(R.id.btnBack).setOnClickListener(v -> finish());

        // Setup Expiration Spinner
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, EXPIRATION_LABELS);
        spinnerExpiration.setAdapter(adapter);
        spinnerExpiration.setSelection(0); // 24 Hours default

        // Passcode toggle listener
        switchPasscode.setOnCheckedChangeListener((buttonView, isChecked) -> {
            etPasscode.setVisibility(isChecked ? View.VISIBLE : View.GONE);
        });

        btnCreateSecureShare.setOnClickListener(v -> submitShareCreation());
    }

    private void submitShareCreation() {
        tvShareError.setVisibility(View.GONE);

        int selectedIndex = spinnerExpiration.getSelectedItemPosition();
        long expiresInSeconds = EXPIRATION_SECONDS[selectedIndex];
        boolean oneTime = switchOneTime.isChecked();
        boolean requireBiometric = switchRequireBiometric.isChecked();
        boolean preventScreenshots = securityPrefs.isScreenshotProtectionEnabled();

        String passcode = null;
        if (switchPasscode.isChecked()) {
            passcode = etPasscode.getText().toString().trim();
            if (passcode.isEmpty()) {
                tvShareError.setText("Please enter a passcode or turn off passcode protection.");
                tvShareError.setVisibility(View.VISIBLE);
                return;
            }
        }

        pbCreatingShare.setVisibility(View.VISIBLE);
        btnCreateSecureShare.setEnabled(false);

        final String finalPasscode = passcode;
        ApiClient.getInstance(this).createShare(
                fileId,
                expiresInSeconds,
                oneTime,
                passcode,
                requireBiometric,
                preventScreenshots,
                new ApiClient.ApiCallback<JSONObject>() {
                    @Override
                    public void onSuccess(JSONObject result) {
                        pbCreatingShare.setVisibility(View.GONE);
                        btnCreateSecureShare.setEnabled(true);

                        try {
                            JSONObject shareObj = result.getJSONObject("share");
                            String shareId = shareObj.getString("id");
                            String rawToken = shareObj.getString("token");
                            long expiresAt = shareObj.getLong("expires_at");

                            // Resolve raw file key if not passed directly in intent (e.g. unwrap from Keystore)
                            String keyForComposite = rawFileKeyBase64;
                            if (keyForComposite == null || keyForComposite.isEmpty()) {
                                FileItem fileItem = SecureDropDatabaseHelper.getInstance(ShareSettingsActivity.this).getFileById(fileId);
                                if (fileItem != null && fileItem.wrappedKey != null) {
                                    SecretKey unwrapped = CryptoManager.unwrapKeyWithKeystore(fileItem.wrappedKey);
                                    keyForComposite = android.util.Base64.encodeToString(unwrapped.getEncoded(), android.util.Base64.URL_SAFE | android.util.Base64.NO_WRAP);
                                }
                            }

                            // Build zero-knowledge composite share code: TOKEN#KEY
                            String compositeCode = rawToken + (keyForComposite != null ? "#" + keyForComposite : "");

                            // Save share record in local SQLite database
                            ShareItem localShare = new ShareItem(
                                    shareId,
                                    fileId,
                                    rawToken,
                                    compositeCode,
                                    expiresAt,
                                    oneTime,
                                    0,
                                    false,
                                    finalPasscode != null,
                                    requireBiometric,
                                    preventScreenshots,
                                    System.currentTimeMillis(),
                                    fileName
                            );
                            SecureDropDatabaseHelper.getInstance(ShareSettingsActivity.this).saveShareItem(localShare);

                            AuditLogger.logEvent(
                                    ShareSettingsActivity.this,
                                    "SHARE_CREATED",
                                    "INFO",
                                    "Secure share created for " + fileName + (oneTime ? " [One-Time]" : ""),
                                    fileName
                            );

                            // Navigate to ShareCreatedActivity
                            Intent intent = new Intent(ShareSettingsActivity.this, ShareCreatedActivity.class);
                            intent.putExtra("share_id", shareId);
                            intent.putExtra("composite_code", compositeCode);
                            intent.putExtra("raw_token", rawToken);
                            intent.putExtra("file_name", fileName);
                            intent.putExtra("expires_at", expiresAt);
                            intent.putExtra("one_time", oneTime);
                            intent.putExtra("has_passcode", finalPasscode != null);
                            intent.putExtra("passcode", finalPasscode);
                            startActivity(intent);
                            finish();
                        } catch (Exception e) {
                            showError("Error parsing share response: " + e.getMessage());
                        }
                    }

                    @Override
                    public void onError(int statusCode, String errorMessage) {
                        pbCreatingShare.setVisibility(View.GONE);
                        btnCreateSecureShare.setEnabled(true);
                        showError("Server rejected share creation (" + statusCode + "): " + errorMessage);
                    }
                }
        );
    }

    private void showError(String msg) {
        tvShareError.setText(msg);
        tvShareError.setVisibility(View.VISIBLE);
    }
}
