package com.securedrop.ui.file;

import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.util.Base64;
import android.view.View;
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
import com.securedrop.data.db.SecureDropDatabaseHelper;
import com.securedrop.data.model.FileItem;
import com.securedrop.network.ApiClient;
import com.securedrop.security.AuditLogger;
import com.securedrop.ui.base.BaseActivity;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.concurrent.Executors;

import javax.crypto.SecretKey;

public class UploadFileActivity extends BaseActivity {

    private Uri selectedFileUri;
    private String selectedFileName = "document.bin";
    private String selectedMimeType = "application/octet-stream";
    private long selectedFileSize = 0;
    private byte[] cachedPlaintextBytes = null;
    private String computedPlaintextSha256 = null;

    private MaterialCardView cardSelectFile, cardFilePreview;
    private TextView tvSelectedFileName, tvSelectedFileSize, tvCryptoAudit, tvProgressStatus, tvUploadError;
    private LinearLayout layoutProgress;
    private ProgressBar pbUpload;
    private MaterialButton btnStartEncryption;

    private final ActivityResultLauncher<String[]> filePickerLauncher =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(), uri -> {
                if (uri != null) {
                    onFileSelected(uri);
                }
            });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_upload_file);

        cardSelectFile = findViewById(R.id.cardSelectFile);
        cardFilePreview = findViewById(R.id.cardFilePreview);
        tvSelectedFileName = findViewById(R.id.tvSelectedFileName);
        tvSelectedFileSize = findViewById(R.id.tvSelectedFileSize);
        tvCryptoAudit = findViewById(R.id.tvCryptoAudit);
        tvProgressStatus = findViewById(R.id.tvProgressStatus);
        tvUploadError = findViewById(R.id.tvUploadError);
        layoutProgress = findViewById(R.id.layoutProgress);
        pbUpload = findViewById(R.id.pbUpload);
        btnStartEncryption = findViewById(R.id.btnStartEncryption);

        findViewById(R.id.btnBack).setOnClickListener(v -> finish());
        cardSelectFile.setOnClickListener(v -> filePickerLauncher.launch(new String[]{"*/*"}));
        btnStartEncryption.setOnClickListener(v -> executeEncryptionAndUpload());
    }

    private void onFileSelected(Uri uri) {
        this.selectedFileUri = uri;
        tvUploadError.setVisibility(View.GONE);

        // Extract metadata using ContentResolver
        Cursor cursor = getContentResolver().query(uri, null, null, null, null);
        if (cursor != null && cursor.moveToFirst()) {
            int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
            int sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE);
            if (nameIndex != -1) selectedFileName = cursor.getString(nameIndex);
            if (sizeIndex != -1) selectedFileSize = cursor.getLong(sizeIndex);
            cursor.close();
        }

        String type = getContentResolver().getType(uri);
        if (type != null) selectedMimeType = type;

        tvSelectedFileName.setText(selectedFileName);
        tvSelectedFileSize.setText("Size: " + (selectedFileSize / 1024) + " KB • MIME: " + selectedMimeType);
        cardFilePreview.setVisibility(View.VISIBLE);
        btnStartEncryption.setEnabled(false);
        tvCryptoAudit.setText("Computing cryptographic SHA-256 hash...");

        // Asynchronously read plaintext bytes and compute SHA-256
        Executors.newSingleThreadExecutor().execute(() -> {
            try {
                InputStream is = getContentResolver().openInputStream(uri);
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                byte[] data = new byte[8192];
                int nRead;
                while ((nRead = is.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }
                buffer.flush();
                is.close();

                cachedPlaintextBytes = buffer.toByteArray();
                selectedFileSize = cachedPlaintextBytes.length;
                computedPlaintextSha256 = CryptoManager.computeSha256(cachedPlaintextBytes);

                runOnUiThread(() -> {
                    tvCryptoAudit.setText("Algorithm: AES-256-GCM (Authenticated)\nKey Protection: Android Keystore Hardware/Software\nPlaintext SHA-256:\n" + computedPlaintextSha256);
                    btnStartEncryption.setEnabled(true);
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    tvUploadError.setText("Error reading file: " + e.getMessage());
                    tvUploadError.setVisibility(View.VISIBLE);
                });
            }
        });
    }

    private void executeEncryptionAndUpload() {
        if (cachedPlaintextBytes == null) return;

        layoutProgress.setVisibility(View.VISIBLE);
        btnStartEncryption.setEnabled(false);
        tvProgressStatus.setText("Generating 256-bit AES key & encrypting with AES-GCM...");

        Executors.newSingleThreadExecutor().execute(() -> {
            try {
                // 1. Generate random 256-bit AES key
                SecretKey fileKey = CryptoManager.generateFileKey();

                // 2. Encrypt locally with AES-256-GCM
                CryptoManager.EncryptedPayload payload = CryptoManager.encrypt(cachedPlaintextBytes, fileKey);

                // 3. Wrap file key with Android Keystore master key for owner storage
                String wrappedKey = CryptoManager.wrapKeyWithKeystore(fileKey);

                // 4. Securely wipe plaintext bytes from memory
                CryptoManager.wipeMemory(cachedPlaintextBytes);
                cachedPlaintextBytes = null;

                runOnUiThread(() -> tvProgressStatus.setText("Uploading encrypted payload over TLS/HTTPS..."));

                // 5. Upload encrypted blob to backend
                ApiClient.getInstance(UploadFileActivity.this).uploadEncryptedFile(
                        selectedFileName,
                        selectedMimeType,
                        payload.ciphertext.length,
                        selectedFileSize,
                        payload.sha256Encrypted,
                        computedPlaintextSha256,
                        payload.getIvHex(),
                        payload.getAuthTagHex(),
                        payload.ciphertext,
                        new ApiClient.ApiCallback<JSONObject>() {
                            @Override
                            public void onSuccess(JSONObject result) {
                                try {
                                    JSONObject fileObj = result.getJSONObject("file");
                                    String fileId = fileObj.getString("id");

                                    // Save file metadata locally with wrapped key
                                    FileItem localItem = new FileItem(
                                            fileId,
                                            selectedFileName,
                                            selectedMimeType,
                                            payload.ciphertext.length,
                                            selectedFileSize,
                                            payload.sha256Encrypted,
                                            computedPlaintextSha256,
                                            payload.getIvHex(),
                                            payload.getAuthTagHex(),
                                            System.currentTimeMillis()
                                    );
                                    SecureDropDatabaseHelper.getInstance(UploadFileActivity.this).saveFileItem(localItem, wrappedKey);

                                    AuditLogger.logEvent(
                                            UploadFileActivity.this,
                                            "FILE_UPLOADED",
                                            "INFO",
                                            "Encrypted and uploaded: " + selectedFileName,
                                            selectedFileName
                                    );

                                    Toast.makeText(UploadFileActivity.this, "File encrypted & uploaded successfully!", Toast.LENGTH_SHORT).show();

                                    // Forward to ShareSettingsActivity
                                    Intent intent = new Intent(UploadFileActivity.this, ShareSettingsActivity.class);
                                    intent.putExtra("file_id", fileId);
                                    intent.putExtra("file_name", selectedFileName);
                                    // Pass raw file key encoded for immediate share creation
                                    String keyB64 = Base64.encodeToString(fileKey.getEncoded(), Base64.URL_SAFE | Base64.NO_WRAP);
                                    intent.putExtra("raw_file_key", keyB64);
                                    startActivity(intent);
                                    finish();
                                } catch (Exception e) {
                                    showError("Upload parse error: " + e.getMessage());
                                }
                            }

                            @Override
                            public void onError(int statusCode, String errorMessage) {
                                showError("Server error (" + statusCode + "): " + errorMessage);
                            }
                        }
                );
            } catch (Exception e) {
                runOnUiThread(() -> showError("Cryptographic error: " + e.getMessage()));
            }
        });
    }

    private void showError(String msg) {
        layoutProgress.setVisibility(View.GONE);
        btnStartEncryption.setEnabled(true);
        tvUploadError.setText(msg);
        tvUploadError.setVisibility(View.VISIBLE);
    }
}
