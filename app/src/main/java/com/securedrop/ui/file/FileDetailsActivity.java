package com.securedrop.ui.file;

import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.button.MaterialButton;
import com.securedrop.R;
import com.securedrop.data.db.SecureDropDatabaseHelper;
import com.securedrop.data.model.FileItem;
import com.securedrop.ui.base.BaseActivity;

public class FileDetailsActivity extends BaseActivity {

    private String fileId;
    private FileItem fileItem;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_file_details);

        fileId = getIntent().getStringExtra("file_id");
        if (fileId == null) {
            finish();
            return;
        }

        fileItem = SecureDropDatabaseHelper.getInstance(this).getFileById(fileId);
        if (fileItem == null) {
            Toast.makeText(this, "File record not found locally", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        findViewById(R.id.btnBack).setOnClickListener(v -> finish());

        TextView tvDetailName = findViewById(R.id.tvDetailName);
        TextView tvDetailSize = findViewById(R.id.tvDetailSize);
        TextView tvDetailEncSha = findViewById(R.id.tvDetailEncSha);
        TextView tvDetailPlainSha = findViewById(R.id.tvDetailPlainSha);
        TextView tvDetailIv = findViewById(R.id.tvDetailIv);
        TextView tvDetailAuthTag = findViewById(R.id.tvDetailAuthTag);
        MaterialButton btnCreateShareForFile = findViewById(R.id.btnCreateShareForFile);

        tvDetailName.setText(fileItem.originalName);
        tvDetailSize.setText("Encrypted: " + fileItem.getFormattedSize() + " • Plaintext: " + (fileItem.plaintextSize / 1024) + " KB");
        tvDetailEncSha.setText(fileItem.sha256Hash);
        tvDetailPlainSha.setText(fileItem.plaintextSha256 != null && !fileItem.plaintextSha256.isEmpty()
                ? fileItem.plaintextSha256 : "Calculated at upload");
        tvDetailIv.setText(fileItem.ivHex);
        tvDetailAuthTag.setText(fileItem.authTagHex);

        btnCreateShareForFile.setOnClickListener(v -> {
            Intent intent = new Intent(FileDetailsActivity.this, ShareSettingsActivity.class);
            intent.putExtra("file_id", fileItem.id);
            intent.putExtra("file_name", fileItem.originalName);
            startActivity(intent);
        });
    }
}
