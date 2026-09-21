package com.securedrop.ui.file;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.securedrop.R;
import com.securedrop.data.db.SecureDropDatabaseHelper;
import com.securedrop.data.model.FileItem;
import com.securedrop.data.model.ShareItem;
import com.securedrop.network.ApiClient;
import com.securedrop.security.AuditLogger;
import com.securedrop.ui.adapter.FilesAdapter;
import com.securedrop.ui.adapter.SharesAdapter;
import com.securedrop.ui.base.BaseActivity;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class MyFilesActivity extends BaseActivity {

    private boolean isFilesTab = true;
    private TextView tabFiles, tabShares, tvEmptyState;
    private RecyclerView rvFiles, rvShares;
    private FilesAdapter filesAdapter;
    private SharesAdapter sharesAdapter;

    private final List<FileItem> fileList = new ArrayList<>();
    private final List<ShareItem> shareList = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_my_files);

        tabFiles = findViewById(R.id.tabFiles);
        tabShares = findViewById(R.id.tabShares);
        tvEmptyState = findViewById(R.id.tvEmptyState);
        rvFiles = findViewById(R.id.rvFiles);
        rvShares = findViewById(R.id.rvShares);

        findViewById(R.id.btnBack).setOnClickListener(v -> finish());
        findViewById(R.id.btnNewUpload).setOnClickListener(v -> startActivity(new Intent(this, UploadFileActivity.class)));

        tabFiles.setOnClickListener(v -> selectTab(true));
        tabShares.setOnClickListener(v -> selectTab(false));

        // Setup Files RecyclerView
        rvFiles.setLayoutManager(new LinearLayoutManager(this));
        filesAdapter = new FilesAdapter(this, fileList, new FilesAdapter.FileClickListener() {
            @Override
            public void onFileClick(FileItem file) {
                Intent intent = new Intent(MyFilesActivity.this, FileDetailsActivity.class);
                intent.putExtra("file_id", file.id);
                startActivity(intent);
            }

            @Override
            public void onShareClick(FileItem file) {
                Intent intent = new Intent(MyFilesActivity.this, ShareSettingsActivity.class);
                intent.putExtra("file_id", file.id);
                intent.putExtra("file_name", file.originalName);
                startActivity(intent);
            }
        });
        rvFiles.setAdapter(filesAdapter);

        // Setup Shares RecyclerView
        rvShares.setLayoutManager(new LinearLayoutManager(this));
        sharesAdapter = new SharesAdapter(this, shareList, new SharesAdapter.ShareActionListener() {
            @Override
            public void onCopyClick(ShareItem share) {
                ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText("SecureDrop Share Code", share.compositeCode);
                clipboard.setPrimaryClip(clip);
                Toast.makeText(MyFilesActivity.this, "Share code copied", Toast.LENGTH_SHORT).show();
            }

            @Override
            public void onRevokeClick(ShareItem share) {
                confirmAndRevokeShare(share);
            }
        });
        rvShares.setAdapter(sharesAdapter);
    }

    @Override
    protected void onResume() {
        super.onResume();
        loadData();
    }

    private void selectTab(boolean files) {
        isFilesTab = files;
        if (files) {
            tabFiles.setBackgroundResource(R.drawable.bg_card_cyber_accent);
            tabFiles.setTextColor(getColor(R.color.brand_accent));
            tabShares.setBackground(null);
            tabShares.setTextColor(getColor(R.color.text_muted));
            rvFiles.setVisibility(View.VISIBLE);
            rvShares.setVisibility(View.GONE);
            tvEmptyState.setVisibility(fileList.isEmpty() ? View.VISIBLE : View.GONE);
            tvEmptyState.setText("No encrypted files yet. Tap '+ Upload' to encrypt a file.");
        } else {
            tabShares.setBackgroundResource(R.drawable.bg_card_cyber_accent);
            tabShares.setTextColor(getColor(R.color.brand_accent));
            tabFiles.setBackground(null);
            tabFiles.setTextColor(getColor(R.color.text_muted));
            rvShares.setVisibility(View.VISIBLE);
            rvFiles.setVisibility(View.GONE);
            tvEmptyState.setVisibility(shareList.isEmpty() ? View.VISIBLE : View.GONE);
            tvEmptyState.setText("No active shares created yet.");
        }
    }

    private void loadData() {
        // Load files
        fileList.clear();
        fileList.addAll(SecureDropDatabaseHelper.getInstance(this).getLocalFiles());
        filesAdapter.notifyDataSetChanged();

        // Load shares
        shareList.clear();
        shareList.addAll(SecureDropDatabaseHelper.getInstance(this).getLocalShares());
        sharesAdapter.notifyDataSetChanged();

        selectTab(isFilesTab);
    }

    private void confirmAndRevokeShare(ShareItem share) {
        new AlertDialog.Builder(this)
                .setTitle("Revoke Share Access?")
                .setMessage("This will immediately terminate access on the backend server. Anyone attempting to download will receive an HTTP 403 Access Revoked error.")
                .setPositiveButton("Revoke Now", (dialog, which) -> {
                    ApiClient.getInstance(this).revokeShare(share.id, new ApiClient.ApiCallback<JSONObject>() {
                        @Override
                        public void onSuccess(JSONObject result) {
                            SecureDropDatabaseHelper.getInstance(MyFilesActivity.this).markShareRevoked(share.id);
                            AuditLogger.logEvent(MyFilesActivity.this, "SHARE_REVOKED", "WARNING",
                                    "Share revoked for: " + share.filename, share.filename);
                            Toast.makeText(MyFilesActivity.this, "Share access successfully revoked.", Toast.LENGTH_LONG).show();
                            loadData();
                        }

                        @Override
                        public void onError(int statusCode, String errorMessage) {
                            Toast.makeText(MyFilesActivity.this, "Revoke failed: " + errorMessage, Toast.LENGTH_SHORT).show();
                        }
                    });
                })
                .setNegativeButton("Cancel", null)
                .show();
    }
}
