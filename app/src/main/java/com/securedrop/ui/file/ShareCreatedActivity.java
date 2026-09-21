package com.securedrop.ui.file;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.button.MaterialButton;
import com.securedrop.R;
import com.securedrop.ui.base.BaseActivity;
import com.securedrop.ui.main.MainActivity;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class ShareCreatedActivity extends BaseActivity {

    private String compositeCode;
    private String fileName;
    private long expiresAt;
    private boolean oneTime;
    private boolean hasPasscode;
    private String passcode;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_share_created);

        compositeCode = getIntent().getStringExtra("composite_code");
        fileName = getIntent().getStringExtra("file_name");
        expiresAt = getIntent().getLongExtra("expires_at", 0);
        oneTime = getIntent().getBooleanExtra("one_time", false);
        hasPasscode = getIntent().getBooleanExtra("has_passcode", false);
        passcode = getIntent().getStringExtra("passcode");

        TextView tvCreatedFileName = findViewById(R.id.tvCreatedFileName);
        TextView tvCompositeCode = findViewById(R.id.tvCompositeCode);
        TextView tvParamExpiration = findViewById(R.id.tvParamExpiration);
        TextView tvParamOneTime = findViewById(R.id.tvParamOneTime);
        TextView tvParamPasscode = findViewById(R.id.tvParamPasscode);
        MaterialButton btnCopyCode = findViewById(R.id.btnCopyCode);
        MaterialButton btnShareIntent = findViewById(R.id.btnShareIntent);
        MaterialButton btnReturnDashboard = findViewById(R.id.btnReturnDashboard);

        tvCreatedFileName.setText(fileName != null ? fileName : "Encrypted Document");
        tvCompositeCode.setText(compositeCode != null ? compositeCode : "");

        SimpleDateFormat sdf = new SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault());
        tvParamExpiration.setText("• Expiration: " + (expiresAt > 0 ? sdf.format(new Date(expiresAt)) : "Server controlled"));
        tvParamOneTime.setText("• Download Policy: " + (oneTime ? "One-time download (Self-destructs)" : "Multiple downloads permitted"));
        tvParamPasscode.setText("• Passcode: " + (hasPasscode ? (passcode != null ? passcode : "Protected") : "None"));

        findViewById(R.id.btnBack).setOnClickListener(v -> finish());

        btnCopyCode.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText("SecureDrop Share Code", compositeCode);
            clipboard.setPrimaryClip(clip);
            Toast.makeText(this, "Secure share code copied to clipboard", Toast.LENGTH_SHORT).show();
        });

        btnShareIntent.setOnClickListener(v -> {
            Intent sendIntent = new Intent();
            sendIntent.setAction(Intent.ACTION_SEND);
            String message = "Here is a secure end-to-end encrypted document shared via SecureDrop:\n\n"
                    + "Document: " + fileName + "\n"
                    + "Share Code: " + compositeCode + "\n"
                    + (hasPasscode && passcode != null ? "Passcode: " + passcode + "\n" : "")
                    + "\nOpen in SecureDrop to verify integrity and decrypt.";
            sendIntent.putExtra(Intent.EXTRA_TEXT, message);
            sendIntent.setType("text/plain");
            startActivity(Intent.createChooser(sendIntent, "Share SecureDrop Code"));
        });

        btnReturnDashboard.setOnClickListener(v -> {
            Intent intent = new Intent(this, MainActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(intent);
            finish();
        });
    }
}
