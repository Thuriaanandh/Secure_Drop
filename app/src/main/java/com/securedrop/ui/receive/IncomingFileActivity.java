package com.securedrop.ui.receive;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.button.MaterialButton;
import com.securedrop.R;
import com.securedrop.crypto.CryptoManager;
import com.securedrop.network.ApiClient;
import com.securedrop.ui.base.BaseActivity;

import org.json.JSONObject;

public class IncomingFileActivity extends BaseActivity {

    private EditText etShareCodeInput;
    private ProgressBar pbLookup;
    private TextView tvLookupError;
    private MaterialButton btnVerifyShare, btnPasteClipboard;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_incoming_file);

        etShareCodeInput = findViewById(R.id.etShareCodeInput);
        pbLookup = findViewById(R.id.pbLookup);
        tvLookupError = findViewById(R.id.tvLookupError);
        btnVerifyShare = findViewById(R.id.btnVerifyShare);
        btnPasteClipboard = findViewById(R.id.btnPasteClipboard);

        findViewById(R.id.btnBack).setOnClickListener(v -> finish());

        btnPasteClipboard.setOnClickListener(v -> {
            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard.hasPrimaryClip() && clipboard.getPrimaryClip().getItemCount() > 0) {
                ClipData.Item item = clipboard.getPrimaryClip().getItemAt(0);
                CharSequence text = item.getText();
                if (text != null) {
                    etShareCodeInput.setText(text.toString().trim());
                }
            }
        });

        btnVerifyShare.setOnClickListener(v -> executeShareLookup());
    }

    private void executeShareLookup() {
        tvLookupError.setVisibility(View.GONE);
        String input = etShareCodeInput.getText().toString().trim();

        if (input.isEmpty()) {
            showError("Please paste or enter a share code.");
            return;
        }

        // Parse token and decryption key fragment
        String[] parsed = CryptoManager.parseCompositeShareCode(input);
        if (parsed == null || parsed[0].isEmpty()) {
            showError("Invalid share code format.");
            return;
        }

        final String token = parsed[0];
        final String fileKeyBase64 = parsed.length > 1 ? parsed[1] : "";

        pbLookup.setVisibility(View.VISIBLE);
        btnVerifyShare.setEnabled(false);

        ApiClient.getInstance(this).lookupShare(token, new ApiClient.ApiCallback<JSONObject>() {
            @Override
            public void onSuccess(JSONObject result) {
                pbLookup.setVisibility(View.GONE);
                btnVerifyShare.setEnabled(true);

                try {
                    JSONObject share = result.getJSONObject("share");

                    Intent intent = new Intent(IncomingFileActivity.this, DownloadVerificationActivity.class);
                    intent.putExtra("token", token);
                    intent.putExtra("file_key_b64", fileKeyBase64);
                    intent.putExtra("share_id", share.getString("id"));
                    intent.putExtra("file_name", share.getString("original_name"));
                    intent.putExtra("mime_type", share.getString("mime_type"));
                    intent.putExtra("encrypted_size", share.getLong("encrypted_size"));
                    intent.putExtra("sha256_hash", share.getString("sha256_hash"));
                    intent.putExtra("plaintext_sha256", share.optString("plaintext_sha256", ""));
                    intent.putExtra("iv_hex", share.getString("iv_hex"));
                    intent.putExtra("auth_tag_hex", share.getString("auth_tag_hex"));
                    intent.putExtra("one_time", share.getBoolean("one_time"));
                    intent.putExtra("require_passcode", share.getBoolean("require_passcode"));
                    intent.putExtra("require_biometric", share.getBoolean("require_biometric"));
                    intent.putExtra("prevent_screenshots", share.getBoolean("prevent_screenshots"));
                    startActivity(intent);
                    finish();
                } catch (Exception e) {
                    showError("Error parsing share data: " + e.getMessage());
                }
            }

            @Override
            public void onError(int statusCode, String errorMessage) {
                pbLookup.setVisibility(View.GONE);
                btnVerifyShare.setEnabled(true);

                if (statusCode == 410) {
                    showError("⚠️ Share Link Inactive: " + errorMessage);
                } else if (statusCode == 403) {
                    showError("⛔ Access Revoked: " + errorMessage);
                } else if (statusCode == 404) {
                    showError("❌ Invalid or Unknown Share Token.");
                } else {
                    showError("Error (" + statusCode + "): " + errorMessage);
                }
            }
        });
    }

    private void showError(String msg) {
        tvLookupError.setText(msg);
        tvLookupError.setVisibility(View.VISIBLE);
    }
}
