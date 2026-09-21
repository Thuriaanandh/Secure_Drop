package com.securedrop.ui.auth;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.securedrop.R;
import com.securedrop.data.pref.SecurityPreferences;
import com.securedrop.network.ApiClient;
import com.securedrop.security.AuditLogger;
import com.securedrop.security.BiometricHelper;
import com.securedrop.ui.main.MainActivity;

import org.json.JSONObject;

public class AuthActivity extends AppCompatActivity {

    private boolean isLoginMode = true;
    private SecurityPreferences prefs;

    private TextView tvAuthTitle, tvAuthSubtitle, tabLogin, tabRegister;
    private TextView lblUsername, lblIdentifier, tvAuthError, tvCurrentServerUrl;
    private EditText etUsername, etIdentifier, etPassword;
    private MaterialButton btnSubmitAuth, btnOfflineDemo;
    private ProgressBar pbAuth;
    private ImageView btnConfigServer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth);

        prefs = new SecurityPreferences(this);

        tvAuthTitle = findViewById(R.id.tvAuthTitle);
        tvAuthSubtitle = findViewById(R.id.tvAuthSubtitle);
        tabLogin = findViewById(R.id.tabLogin);
        tabRegister = findViewById(R.id.tabRegister);
        lblUsername = findViewById(R.id.lblUsername);
        lblIdentifier = findViewById(R.id.lblIdentifier);
        tvAuthError = findViewById(R.id.tvAuthError);
        tvCurrentServerUrl = findViewById(R.id.tvCurrentServerUrl);

        etUsername = findViewById(R.id.etUsername);
        etIdentifier = findViewById(R.id.etIdentifier);
        etPassword = findViewById(R.id.etPassword);
        btnSubmitAuth = findViewById(R.id.btnSubmitAuth);
        btnOfflineDemo = findViewById(R.id.btnOfflineDemo);
        pbAuth = findViewById(R.id.pbAuth);
        btnConfigServer = findViewById(R.id.btnConfigServer);

        updateServerDisplay();

        tabLogin.setOnClickListener(v -> setAuthMode(true));
        tabRegister.setOnClickListener(v -> setAuthMode(false));

        btnConfigServer.setOnClickListener(v -> showServerConfigDialog());
        btnSubmitAuth.setOnClickListener(v -> submitAuth());
        btnOfflineDemo.setOnClickListener(v -> enterOfflineDemoMode());
    }

    private void updateServerDisplay() {
        tvCurrentServerUrl.setText("Server: " + prefs.getServerUrl());
    }

    private void setAuthMode(boolean login) {
        isLoginMode = login;
        tvAuthError.setVisibility(View.GONE);
        if (login) {
            tabLogin.setBackgroundResource(R.drawable.bg_card_cyber_accent);
            tabLogin.setTextColor(getColor(R.color.brand_accent));
            tabRegister.setBackground(null);
            tabRegister.setTextColor(getColor(R.color.text_muted));

            tvAuthTitle.setText("Secure Sign In");
            tvAuthSubtitle.setText("Authenticate to access your encrypted vault.");
            lblUsername.setVisibility(View.GONE);
            etUsername.setVisibility(View.GONE);
            lblIdentifier.setText("Email or Username");
            btnSubmitAuth.setText("Log In");
        } else {
            tabRegister.setBackgroundResource(R.drawable.bg_card_cyber_accent);
            tabRegister.setTextColor(getColor(R.color.brand_accent));
            tabLogin.setBackground(null);
            tabLogin.setTextColor(getColor(R.color.text_muted));

            tvAuthTitle.setText("Create Vault Account");
            tvAuthSubtitle.setText("Register identity with salted bcrypt password security.");
            lblUsername.setVisibility(View.VISIBLE);
            etUsername.setVisibility(View.VISIBLE);
            lblIdentifier.setText("Email Address");
            btnSubmitAuth.setText("Register Account");
        }
    }

    private void showServerConfigDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this, R.style.SecureDropCard);
        builder.setTitle("Server Network Endpoint");

        final EditText input = new EditText(this);
        input.setText(prefs.getServerUrl());
        input.setTextColor(getColor(R.color.text_primary));
        input.setBackgroundResource(R.drawable.bg_input_field);
        input.setPadding(32, 32, 32, 32);
        builder.setView(input);

        builder.setPositiveButton("Save", (dialog, which) -> {
            String newUrl = input.getText().toString().trim();
            if (!newUrl.isEmpty()) {
                prefs.setServerUrl(newUrl);
                updateServerDisplay();
                Toast.makeText(this, "Server URL updated", Toast.LENGTH_SHORT).show();
            }
        });
        builder.setNegativeButton("Cancel", null);
        builder.show();
    }

    private void submitAuth() {
        tvAuthError.setVisibility(View.GONE);
        String password = etPassword.getText().toString().trim();

        if (password.length() < 8) {
            tvAuthError.setText("Password must be at least 8 characters long.");
            tvAuthError.setVisibility(View.VISIBLE);
            return;
        }

        pbAuth.setVisibility(View.VISIBLE);
        btnSubmitAuth.setEnabled(false);

        if (isLoginMode) {
            String identifier = etIdentifier.getText().toString().trim();
            if (identifier.isEmpty()) {
                showError("Please enter your email or username.");
                return;
            }

            ApiClient.getInstance(this).login(identifier, password, new ApiClient.ApiCallback<JSONObject>() {
                @Override
                public void onSuccess(JSONObject result) {
                    pbAuth.setVisibility(View.GONE);
                    btnSubmitAuth.setEnabled(true);
                    try {
                        String token = result.getString("token");
                        JSONObject user = result.getJSONObject("user");
                        String userId = user.getString("id");
                        String username = user.getString("username");
                        String email = user.getString("email");

                        prefs.saveUserSession(token, userId, username, email);

                        AuditLogger.logEvent(AuthActivity.this, "AUTHENTICATION_SUCCESS", "INFO",
                                "User logged in: " + username, null);

                        checkBiometricEnrollment();
                    } catch (Exception e) {
                        showError("Failed to parse login response: " + e.getMessage());
                    }
                }

                @Override
                public void onError(int statusCode, String errorMessage) {
                    pbAuth.setVisibility(View.GONE);
                    btnSubmitAuth.setEnabled(true);
                    String hint = (statusCode == 0 || errorMessage.contains("connect") || errorMessage.contains("Failed to connect"))
                            ? "\n\nServer unreachable. Start backend with 'npm start', or tap 'Offline Demo Mode' below."
                            : "";
                    showError(errorMessage + hint);
                    AuditLogger.logEvent(AuthActivity.this, "AUTHENTICATION_FAILURE", "WARNING",
                            "Login failed for: " + identifier, null);
                }
            });
        } else {
            String username = etUsername.getText().toString().trim();
            String email = etIdentifier.getText().toString().trim();

            if (username.isEmpty() || email.isEmpty()) {
                showError("Username and email are required.");
                return;
            }

            ApiClient.getInstance(this).register(username, email, password, new ApiClient.ApiCallback<JSONObject>() {
                @Override
                public void onSuccess(JSONObject result) {
                    pbAuth.setVisibility(View.GONE);
                    btnSubmitAuth.setEnabled(true);
                    try {
                        String token = result.getString("token");
                        JSONObject user = result.getJSONObject("user");
                        String userId = user.getString("id");

                        prefs.saveUserSession(token, userId, username, email);

                        AuditLogger.logEvent(AuthActivity.this, "AUTHENTICATION_SUCCESS", "INFO",
                                "User registered: " + username, null);

                        checkBiometricEnrollment();
                    } catch (Exception e) {
                        showError("Error: " + e.getMessage());
                    }
                }

                @Override
                public void onError(int statusCode, String errorMessage) {
                    pbAuth.setVisibility(View.GONE);
                    btnSubmitAuth.setEnabled(true);
                    String hint = (statusCode == 0 || errorMessage.contains("connect") || errorMessage.contains("Failed to connect"))
                            ? "\n\nServer unreachable. Start backend with 'npm start', or tap 'Offline Demo Mode' below."
                            : "";
                    showError(errorMessage + hint);
                }
            });
        }
    }

    private void enterOfflineDemoMode() {
        prefs.saveUserSession("offline_demo_token_jwt", "demo_user_001", "Demo Analyst", "analyst@securedrop.local");
        prefs.setTestModeEnabled(true);
        AuditLogger.logEvent(this, "OFFLINE_DEMO_LOGIN", "INFO",
                "Entered local Offline Demo Mode (bypassed backend server)", null);
        Toast.makeText(this, "Signed in via Offline Demo Mode", Toast.LENGTH_SHORT).show();
        checkBiometricEnrollment();
    }

    private void checkBiometricEnrollment() {
        if (BiometricHelper.isBiometricAvailable(this)) {
            new AlertDialog.Builder(this)
                    .setTitle("Enable Biometric Unlock?")
                    .setMessage("Protect SecureDrop with fingerprint / face biometric authentication for seamless, high-security access.")
                    .setPositiveButton("Enable", (dialog, which) -> {
                        prefs.setBiometricLockEnabled(true);
                        proceedToMain();
                    })
                    .setNegativeButton("Maybe Later", (dialog, which) -> {
                        prefs.setBiometricLockEnabled(false);
                        proceedToMain();
                    })
                    .setCancelable(false)
                    .show();
        } else {
            proceedToMain();
        }
    }

    private void proceedToMain() {
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
        finish();
    }

    private void showError(String msg) {
        pbAuth.setVisibility(View.GONE);
        btnSubmitAuth.setEnabled(true);
        tvAuthError.setText(msg);
        tvAuthError.setVisibility(View.VISIBLE);
    }
}
