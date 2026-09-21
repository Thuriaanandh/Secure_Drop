package com.securedrop.ui.main;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.securedrop.BuildConfig;
import com.securedrop.R;
import com.securedrop.data.db.SecureDropDatabaseHelper;
import com.securedrop.data.model.FileItem;
import com.securedrop.data.model.SecurityLogItem;
import com.securedrop.security.SecurityScoreCalculator;
import com.securedrop.ui.adapter.AuditLogsAdapter;
import com.securedrop.ui.adapter.FilesAdapter;
import com.securedrop.ui.audit.AccessLogsActivity;
import com.securedrop.ui.base.BaseActivity;
import com.securedrop.ui.file.FileDetailsActivity;
import com.securedrop.ui.file.MyFilesActivity;
import com.securedrop.ui.file.ShareSettingsActivity;
import com.securedrop.ui.file.UploadFileActivity;
import com.securedrop.ui.receive.IncomingFileActivity;
import com.securedrop.ui.security.SecurityCenterActivity;
import com.securedrop.ui.security.SecurityDemoActivity;
import com.securedrop.ui.security.SettingsActivity;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends BaseActivity {

    private TextView tvUserGreeting, tvScoreNumber, tvEmptyFiles;
    private RecyclerView rvRecentFiles, rvRecentLogs;
    private MaterialButton btnDemoScreen;
    private ImageView btnSettings;
    private FilesAdapter filesAdapter;
    private AuditLogsAdapter logsAdapter;
    private final List<FileItem> fileList = new ArrayList<>();
    private final List<SecurityLogItem> logList = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvUserGreeting = findViewById(R.id.tvUserGreeting);
        tvScoreNumber = findViewById(R.id.tvScoreNumber);
        tvEmptyFiles = findViewById(R.id.tvEmptyFiles);
        rvRecentFiles = findViewById(R.id.rvRecentFiles);
        rvRecentLogs = findViewById(R.id.rvRecentLogs);
        btnDemoScreen = findViewById(R.id.btnDemoScreen);
        btnSettings = findViewById(R.id.btnSettings);

        // Configure greeting with authenticated user
        String username = securityPrefs.getUsername();
        tvUserGreeting.setText("Logged in as @" + username);

        // Security Demo button: only visible in debug builds or test mode
        if (BuildConfig.IS_TEST_MODE_ENABLED || securityPrefs.isTestModeEnabled()) {
            btnDemoScreen.setVisibility(View.VISIBLE);
            btnDemoScreen.setOnClickListener(v -> startActivity(new Intent(MainActivity.this, SecurityDemoActivity.class)));
        } else {
            btnDemoScreen.setVisibility(View.GONE);
        }

        // Setup RecyclerViews
        rvRecentFiles.setLayoutManager(new LinearLayoutManager(this));
        filesAdapter = new FilesAdapter(this, fileList, new FilesAdapter.FileClickListener() {
            @Override
            public void onFileClick(FileItem file) {
                Intent intent = new Intent(MainActivity.this, FileDetailsActivity.class);
                intent.putExtra("file_id", file.id);
                startActivity(intent);
            }

            @Override
            public void onShareClick(FileItem file) {
                Intent intent = new Intent(MainActivity.this, ShareSettingsActivity.class);
                intent.putExtra("file_id", file.id);
                intent.putExtra("file_name", file.originalName);
                startActivity(intent);
            }
        });
        rvRecentFiles.setAdapter(filesAdapter);

        rvRecentLogs.setLayoutManager(new LinearLayoutManager(this));
        logsAdapter = new AuditLogsAdapter(this, logList);
        rvRecentLogs.setAdapter(logsAdapter);

        // Navigation actions
        findViewById(R.id.cardSecurityScore).setOnClickListener(v -> startActivity(new Intent(MainActivity.this, SecurityCenterActivity.class)));
        findViewById(R.id.btnQuickSend).setOnClickListener(v -> startActivity(new Intent(MainActivity.this, UploadFileActivity.class)));
        findViewById(R.id.btnQuickReceive).setOnClickListener(v -> startActivity(new Intent(MainActivity.this, IncomingFileActivity.class)));
        findViewById(R.id.btnNavMyFiles).setOnClickListener(v -> startActivity(new Intent(MainActivity.this, MyFilesActivity.class)));
        findViewById(R.id.btnViewAllFiles).setOnClickListener(v -> startActivity(new Intent(MainActivity.this, MyFilesActivity.class)));
        findViewById(R.id.btnNavAuditLogs).setOnClickListener(v -> startActivity(new Intent(MainActivity.this, AccessLogsActivity.class)));
        findViewById(R.id.btnViewAllLogs).setOnClickListener(v -> startActivity(new Intent(MainActivity.this, AccessLogsActivity.class)));
        btnSettings.setOnClickListener(v -> startActivity(new Intent(MainActivity.this, SettingsActivity.class)));
    }

    @Override
    protected void onResume() {
        super.onResume();
        loadDashboardData();
    }

    private void loadDashboardData() {
        // Compute security score
        SecurityScoreCalculator.ScoreResult scoreResult = SecurityScoreCalculator.computeScore(this);
        tvScoreNumber.setText(scoreResult.totalScore + " / 100");

        // Load recent files
        List<FileItem> allFiles = SecureDropDatabaseHelper.getInstance(this).getLocalFiles();
        fileList.clear();
        int maxFiles = Math.min(allFiles.size(), 3);
        for (int i = 0; i < maxFiles; i++) {
            fileList.add(allFiles.get(i));
        }
        filesAdapter.notifyDataSetChanged();
        tvEmptyFiles.setVisibility(fileList.isEmpty() ? View.VISIBLE : View.GONE);

        // Load recent audit logs
        List<SecurityLogItem> allLogs = SecureDropDatabaseHelper.getInstance(this).getAuditLogs();
        logList.clear();
        int maxLogs = Math.min(allLogs.size(), 5);
        for (int i = 0; i < maxLogs; i++) {
            logList.add(allLogs.get(i));
        }
        logsAdapter.notifyDataSetChanged();
    }
}
