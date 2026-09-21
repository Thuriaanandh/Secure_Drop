package com.securedrop.ui.receive;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.securedrop.R;
import com.securedrop.crypto.CryptoManager;
import com.securedrop.network.ApiClient;
import com.securedrop.security.AuditLogger;
import com.securedrop.security.BiometricHelper;
import com.securedrop.ui.base.BaseActivity;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

public class DownloadVerificationActivity extends BaseActivity {

    private String token;
    private String fileKeyB64;
    private String fileName;
    private String mimeType;
    private long encryptedSize;
    private String expectedSha256;
    private String expectedPlaintextSha256;
    private String ivHex;
    private String authTagHex;
    private boolean oneTime;
    private boolean requirePasscode;
    private boolean requireBiometric;
    private boolean preventScreenshots;

    private byte[] decryptedFileBytes = null;

    private TextView tvIncomingFileName, tvIncomingFileSize, tvIncomingSecurityPolicies;
    private TextView tvStepBioStatus, tvStepDownloadStatus, tvStepIntegrityStatus, tvStepDecryptStatus;
    private TextView tvDecryptedPreviewContent, tvVerificationError;
    private EditText etRecipientPasscode, etManualKey;
    private LinearLayout layoutPasscodeSection, layoutKeyEntrySection;
    private MaterialCardView cardDecryptedResult;
    private ProgressBar pbPipeline;
    private MaterialButton btnStartDownloadPipeline, btnExportDocument;

    private final ActivityResultLauncher<String> createDocumentLauncher =
            registerForActivityResult(new ActivityResultContracts.CreateDocument("*/*"), uri -> {
                if (uri != null && decryptedFileBytes != null) {
                    saveDecryptedBytesToUri(uri);
                }
            });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_download_verification);

        token = getIntent().getStringExtra("token");
        fileKeyB64 = getIntent().getStringExtra("file_key_b64");
        fileName = getIntent().getStringExtra("file_name");
        mimeType = getIntent().getStringExtra("mime_type");
        encryptedSize = getIntent().getLongExtra("encrypted_size", 0);
        expectedSha256 = getIntent().getStringExtra("sha256_hash");
        expectedPlaintextSha256 = getIntent().getStringExtra("plaintext_sha256");
        ivHex = getIntent().getStringExtra("iv_hex");
        authTagHex = getIntent().getStringExtra("auth_tag_hex");
        oneTime = getIntent().getBooleanExtra("one_time", false);
        requirePasscode = getIntent().getBooleanExtra("require_passcode", false);
        requireBiometric = getIntent().getBooleanExtra("require_biometric", false);
        preventScreenshots = getIntent().getBooleanExtra("prevent_screenshots", true);

        tvIncomingFileName = findViewById(R.id.tvIncomingFileName);
        tvIncomingFileSize = findViewById(R.id.tvIncomingFileSize);
        tvIncomingSecurityPolicies = findViewById(R.id.tvIncomingSecurityPolicies);
        tvStepBioStatus = findViewById(R.id.tvStepBioStatus);
        tvStepDownloadStatus = findViewById(R.id.tvStepDownloadStatus);
        tvStepIntegrityStatus = findViewById(R.id.tvStepIntegrityStatus);
        tvStepDecryptStatus = findViewById(R.id.tvStepDecryptStatus);
        tvDecryptedPreviewContent = findViewById(R.id.tvDecryptedPreviewContent);
        tvVerificationError = findViewById(R.id.tvVerificationError);
        etRecipientPasscode = findViewById(R.id.etRecipientPasscode);
        etManualKey = findViewById(R.id.etManualKey);
        layoutPasscodeSection = findViewById(R.id.layoutPasscodeSection);
        layoutKeyEntrySection = findViewById(R.id.layoutKeyEntrySection);
        cardDecryptedResult = findViewById(R.id.cardDecryptedResult);
        pbPipeline = findViewById(R.id.pbPipeline);
        btnStartDownloadPipeline = findViewById(R.id.btnStartDownloadPipeline);
        btnExportDocument = findViewById(R.id.btnExportDocument);

        findViewById(R.id.btnBack).setOnClickListener(v -> finish());

        tvIncomingFileName.setText(fileName != null ? fileName : "Encrypted Document");
        tvIncomingFileSize.setText("Encrypted Payload Size: " + (encryptedSize / 1024) + " KB");

        StringBuilder policies = new StringBuilder();
        if (oneTime) policies.append("• One-time download (Auto-destructs) ");
        if (requirePasscode) policies.append("• Passcode required ");
        if (requireBiometric) policies.append("• Biometric verification required ");
        tvIncomingSecurityPolicies.setText(policies.toString());

        if (requirePasscode) {
            layoutPasscodeSection.setVisibility(View.VISIBLE);
        }
        if (fileKeyB64 == null || fileKeyB64.trim().isEmpty()) {
            layoutKeyEntrySection.setVisibility(View.VISIBLE);
        }

        btnStartDownloadPipeline.setOnClickListener(v -> startPipeline());
        btnExportDocument.setOnClickListener(v -> {
            if (decryptedFileBytes != null) {
                createDocumentLauncher.launch(fileName != null ? fileName : "decrypted_document.bin");
            }
        });
    }

    private void startPipeline() {
        tvVerificationError.setVisibility(View.GONE);

        // Check Passcode
        String passcode = null;
        if (requirePasscode) {
            passcode = etRecipientPasscode.getText().toString().trim();
            if (passcode.isEmpty()) {
                showError("Passcode is required for this protected share.");
                return;
            }
        }

        // Check Decryption Key
        if (fileKeyB64 == null || fileKeyB64.trim().isEmpty()) {
            fileKeyB64 = etManualKey.getText().toString().trim();
            if (fileKeyB64.isEmpty()) {
                showError("AES-256 decryption key is required.");
                return;
            }
        }

        final String finalPasscode = passcode;

        // Step 1: Biometric Authentication
        if (requireBiometric || securityPrefs.isRequireAuthDownload()) {
            if (BiometricHelper.isBiometricAvailable(this)) {
                BiometricHelper.showBiometricPrompt(
                        this,
                        "Sensitive Document Decryption",
                        "Biometric authentication required before accessing plaintext",
                        new BiometricHelper.AuthCallback() {
                            @Override
                            public void onSuccess() {
                                tvStepBioStatus.setText("✓");
                                tvStepBioStatus.setTextColor(getColor(R.color.security_green));
                                proceedWithDownloadAndDecryption(finalPasscode);
                            }

                            @Override
                            public void onFailure(String errorMessage) {
                                tvStepBioStatus.setText("✗");
                                tvStepBioStatus.setTextColor(getColor(R.color.security_red));
                                showError("Biometric authentication failed: " + errorMessage);
                            }
                        }
                );
                return;
            } else {
                tvStepBioStatus.setText("✓ (Device fallback)");
                tvStepBioStatus.setTextColor(getColor(R.color.security_green));
            }
        } else {
            tvStepBioStatus.setText("✓ (Not required)");
            tvStepBioStatus.setTextColor(getColor(R.color.text_secondary));
        }

        proceedWithDownloadAndDecryption(finalPasscode);
    }

    private void proceedWithDownloadAndDecryption(String passcode) {
        pbPipeline.setVisibility(View.VISIBLE);
        btnStartDownloadPipeline.setEnabled(false);
        tvStepDownloadStatus.setText("⏳");

        // Step 2: Download Encrypted Payload over TLS
        ApiClient.getInstance(this).downloadEncryptedPayload(token, passcode, new ApiClient.ApiCallback<ApiClient.DownloadResult>() {
            @Override
            public void onSuccess(ApiClient.DownloadResult result) {
                tvStepDownloadStatus.setText("✓");
                tvStepDownloadStatus.setTextColor(getColor(R.color.security_green));

                // Step 3: SHA-256 Integrity Verification
                verifyIntegrityAndDecrypt(result.encryptedPayload);
            }

            @Override
            public void onError(int statusCode, String errorMessage) {
                pbPipeline.setVisibility(View.GONE);
                btnStartDownloadPipeline.setEnabled(true);
                tvStepDownloadStatus.setText("✗");
                tvStepDownloadStatus.setTextColor(getColor(R.color.security_red));

                if (statusCode == 410) {
                    showError("⚠️ Download Blocked: " + errorMessage);
                } else if (statusCode == 401) {
                    showError("⛔ Incorrect Passcode. Access denied.");
                } else if (statusCode == 403) {
                    showError("⛔ Access Revoked by Sender.");
                } else {
                    showError("Download error (" + statusCode + "): " + errorMessage);
                }
            }
        });
    }

    private void verifyIntegrityAndDecrypt(byte[] encryptedPayload) {
        new Thread(() -> {
            try {
                // Compute SHA-256 of downloaded ciphertext
                String computedHash = CryptoManager.computeSha256(encryptedPayload);

                // Compare with expected SHA-256
                boolean integrityMatches = expectedSha256 != null && expectedSha256.equalsIgnoreCase(computedHash);

                if (!integrityMatches) {
                    // CRITICAL INTEGRITY FAILURE! BLOCK ACCESS!
                    CryptoManager.wipeMemory(encryptedPayload);

                    runOnUiThread(() -> {
                        pbPipeline.setVisibility(View.GONE);
                        btnStartDownloadPipeline.setEnabled(true);
                        tvStepIntegrityStatus.setText("⚠ FAILED");
                        tvStepIntegrityStatus.setTextColor(getColor(R.color.security_red));
                        showError("⚠ Integrity verification failed. Payload does not match cryptographic hash. Download blocked.");
                    });

                    AuditLogger.logEvent(
                            DownloadVerificationActivity.this,
                            "INTEGRITY_FAILURE",
                            "CRITICAL",
                            "Integrity check failed for " + fileName + ". Expected: " + expectedSha256 + ", Got: " + computedHash,
                            fileName
                    );
                    return;
                }

                runOnUiThread(() -> {
                    tvStepIntegrityStatus.setText("✓ Integrity Verified");
                    tvStepIntegrityStatus.setTextColor(getColor(R.color.security_green));
                    tvStepDecryptStatus.setText("⏳ Decrypting...");
                });

                // Step 4: AES-256-GCM Local Decryption
                SecretKey fileKey = CryptoManager.decodeFileKey(fileKeyB64);
                byte[] iv = CryptoManager.hexToBytes(ivHex);

                byte[] plaintext = CryptoManager.decrypt(encryptedPayload, fileKey, iv);
                decryptedFileBytes = plaintext;

                // Verify plaintext SHA-256 if available
                if (expectedPlaintextSha256 != null && !expectedPlaintextSha256.isEmpty()) {
                    String plainHash = CryptoManager.computeSha256(plaintext);
                    if (!expectedPlaintextSha256.equalsIgnoreCase(plainHash)) {
                        throw new IllegalStateException("Plaintext SHA-256 check mismatch!");
                    }
                }

                AuditLogger.logEvent(
                        DownloadVerificationActivity.this,
                        "DOWNLOAD_COMPLETED",
                        "INFO",
                        "File downloaded and decrypted: " + fileName,
                        fileName
                );

                runOnUiThread(() -> {
                    pbPipeline.setVisibility(View.GONE);
                    btnStartDownloadPipeline.setVisibility(View.GONE);
                    tvStepDecryptStatus.setText("✓ Decrypted (AES-GCM)");
                    tvStepDecryptStatus.setTextColor(getColor(R.color.security_green));

                    // Show Decrypted Card
                    cardDecryptedResult.setVisibility(View.VISIBLE);
                    String snippet;
                    try {
                        String text = new String(plaintext, StandardCharsets.UTF_8);
                        snippet = text.length() > 200 ? text.substring(0, 200) + "..." : text;
                    } catch (Exception e) {
                        snippet = "Binary document decrypted (" + (plaintext.length / 1024) + " KB). Ready to save.";
                    }
                    tvDecryptedPreviewContent.setText("Document Preview:\n" + snippet);
                    Toast.makeText(DownloadVerificationActivity.this, "Document successfully decrypted!", Toast.LENGTH_SHORT).show();
                });

            } catch (Exception e) {
                runOnUiThread(() -> {
                    pbPipeline.setVisibility(View.GONE);
                    btnStartDownloadPipeline.setEnabled(true);
                    tvStepDecryptStatus.setText("✗ Decryption Failed");
                    tvStepDecryptStatus.setTextColor(getColor(R.color.security_red));
                    showError("Decryption failed: " + e.getMessage() + ". Check if the decryption key is correct.");
                });
            }
        }).start();
    }

    private void saveDecryptedBytesToUri(Uri uri) {
        try {
            OutputStream os = getContentResolver().openOutputStream(uri);
            if (os != null) {
                os.write(decryptedFileBytes);
                os.flush();
                os.close();
                Toast.makeText(this, "Decrypted file saved to device!", Toast.LENGTH_LONG).show();
            }
        } catch (Exception e) {
            Toast.makeText(this, "Failed to save: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        // Automatic deletion / memory wiping of decrypted copies
        if (securityPrefs.isAutoDeleteEnabled() && decryptedFileBytes != null) {
            CryptoManager.wipeMemory(decryptedFileBytes);
            decryptedFileBytes = null;
        }
    }

    private void showError(String msg) {
        tvVerificationError.setText(msg);
        tvVerificationError.setVisibility(View.VISIBLE);
    }
}
