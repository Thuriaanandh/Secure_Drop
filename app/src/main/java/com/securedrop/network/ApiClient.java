package com.securedrop.network;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import com.securedrop.data.pref.SecurityPreferences;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ApiClient {

    private static ApiClient instance;
    private final Context context;
    private final SecurityPreferences prefs;
    private final ExecutorService executor = Executors.newFixedThreadPool(4);
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    public interface ApiCallback<T> {
        void onSuccess(T result);
        void onError(int statusCode, String errorMessage);
    }

    public static synchronized ApiClient getInstance(Context context) {
        if (instance == null) {
            instance = new ApiClient(context.getApplicationContext());
        }
        return instance;
    }

    private ApiClient(Context context) {
        this.context = context;
        this.prefs = new SecurityPreferences(context);
    }

    private String getBaseUrl() {
        String url = prefs.getServerUrl();
        if (url == null || url.trim().isEmpty()) {
            return SecurityPreferences.DEFAULT_SERVER_URL;
        }
        if (url.endsWith("/")) {
            return url.substring(0, url.length() - 1);
        }
        return url;
    }

    // --- Authentication ---

    public void register(String username, String email, String password, ApiCallback<JSONObject> callback) {
        executor.execute(() -> {
            try {
                JSONObject body = new JSONObject();
                body.put("username", username);
                body.put("email", email);
                body.put("password", password);

                executeJsonRequest("POST", "/api/auth/register", body, callback);
            } catch (Exception e) {
                postError(callback, -1, e.getMessage());
            }
        });
    }

    public void login(String identifier, String password, ApiCallback<JSONObject> callback) {
        executor.execute(() -> {
            try {
                JSONObject body = new JSONObject();
                body.put("identifier", identifier);
                body.put("password", password);

                executeJsonRequest("POST", "/api/auth/login", body, callback);
            } catch (Exception e) {
                postError(callback, -1, e.getMessage());
            }
        });
    }

    // --- Files (Encrypted Payload Upload) ---

    public void uploadEncryptedFile(
            String originalName,
            String mimeType,
            long encryptedSize,
            long plaintextSize,
            String sha256Hash,
            String plaintextSha256,
            String ivHex,
            String authTagHex,
            byte[] encryptedBytes,
            ApiCallback<JSONObject> callback) {

        executor.execute(() -> {
            HttpURLConnection conn = null;
            try {
                String boundary = "----SecureDropUploadBoundary" + System.currentTimeMillis();
                URL url = new URL(getBaseUrl() + "/api/files/upload");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setConnectTimeout(60000);
                conn.setReadTimeout(60000);
                conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);

                String authToken = prefs.getAuthToken();
                if (authToken != null) {
                    conn.setRequestProperty("Authorization", "Bearer " + authToken);
                }

                DataOutputStream dos = new DataOutputStream(conn.getOutputStream());

                writeFormField(dos, boundary, "original_name", originalName);
                writeFormField(dos, boundary, "mime_type", mimeType);
                writeFormField(dos, boundary, "encrypted_size", String.valueOf(encryptedSize));
                writeFormField(dos, boundary, "plaintext_size", String.valueOf(plaintextSize));
                writeFormField(dos, boundary, "sha256_hash", sha256Hash);
                writeFormField(dos, boundary, "plaintext_sha256", plaintextSha256);
                writeFormField(dos, boundary, "iv_hex", ivHex);
                writeFormField(dos, boundary, "auth_tag_hex", authTagHex);

                // File field
                dos.writeBytes("--" + boundary + "\r\n");
                dos.writeBytes("Content-Disposition: form-data; name=\"encrypted_file\"; filename=\"" + originalName + ".enc\"\r\n");
                dos.writeBytes("Content-Type: application/octet-stream\r\n\r\n");
                dos.write(encryptedBytes);
                dos.writeBytes("\r\n");
                dos.writeBytes("--" + boundary + "--\r\n");
                dos.flush();
                dos.close();

                int statusCode = conn.getResponseCode();
                InputStream is = (statusCode >= 200 && statusCode < 300) ? conn.getInputStream() : conn.getErrorStream();
                String responseStr = readStreamToString(is);

                if (statusCode >= 200 && statusCode < 300) {
                    JSONObject json = new JSONObject(responseStr);
                    postSuccess(callback, json);
                } else {
                    String err = parseErrorMessage(responseStr);
                    postError(callback, statusCode, err);
                }
            } catch (Exception e) {
                postError(callback, -1, "Connection error: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        });
    }

    private void writeFormField(DataOutputStream dos, String boundary, String name, String value) throws Exception {
        dos.writeBytes("--" + boundary + "\r\n");
        dos.writeBytes("Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n");
        dos.write(value.getBytes(StandardCharsets.UTF_8));
        dos.writeBytes("\r\n");
    }

    // --- Shares Management ---

    public void createShare(
            String fileId,
            long expiresInSeconds,
            boolean oneTime,
            String passcode,
            boolean requireBiometric,
            boolean preventScreenshots,
            ApiCallback<JSONObject> callback) {

        executor.execute(() -> {
            try {
                JSONObject body = new JSONObject();
                body.put("file_id", fileId);
                body.put("expires_in_seconds", expiresInSeconds);
                body.put("one_time", oneTime);
                if (passcode != null && !passcode.trim().isEmpty()) {
                    body.put("passcode", passcode.trim());
                }
                body.put("require_biometric", requireBiometric);
                body.put("prevent_screenshots", preventScreenshots);

                executeJsonRequest("POST", "/api/shares", body, callback);
            } catch (Exception e) {
                postError(callback, -1, e.getMessage());
            }
        });
    }

    public void revokeShare(String shareId, ApiCallback<JSONObject> callback) {
        executeJsonRequest("POST", "/api/shares/" + shareId + "/revoke", new JSONObject(), callback);
    }

    public void lookupShare(String token, ApiCallback<JSONObject> callback) {
        executeJsonRequest("GET", "/api/shares/lookup/" + token, null, callback);
    }

    // --- Download Encrypted File ---

    public static class DownloadResult {
        public final byte[] encryptedPayload;
        public final String sha256Header;

        public DownloadResult(byte[] encryptedPayload, String sha256Header) {
            this.encryptedPayload = encryptedPayload;
            this.sha256Header = sha256Header;
        }
    }

    public void downloadEncryptedPayload(String token, String passcode, ApiCallback<DownloadResult> callback) {
        executor.execute(() -> {
            HttpURLConnection conn = null;
            try {
                URL url = new URL(getBaseUrl() + "/api/shares/download/" + token);
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setConnectTimeout(60000);
                conn.setReadTimeout(60000);
                conn.setRequestProperty("Content-Type", "application/json");

                JSONObject body = new JSONObject();
                if (passcode != null) {
                    body.put("passcode", passcode);
                }

                DataOutputStream dos = new DataOutputStream(conn.getOutputStream());
                dos.write(body.toString().getBytes(StandardCharsets.UTF_8));
                dos.flush();
                dos.close();

                int statusCode = conn.getResponseCode();
                if (statusCode == 200) {
                    String sha256Header = conn.getHeaderField("X-Encrypted-SHA256");
                    InputStream is = conn.getInputStream();
                    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    byte[] data = new byte[8192];
                    int read;
                    while ((read = is.read(data, 0, data.length)) != -1) {
                        buffer.write(data, 0, read);
                    }
                    buffer.flush();
                    is.close();

                    postSuccess(callback, new DownloadResult(buffer.toByteArray(), sha256Header));
                } else {
                    InputStream errIs = conn.getErrorStream();
                    String errStr = readStreamToString(errIs);
                    String err = parseErrorMessage(errStr);
                    postError(callback, statusCode, err);
                }
            } catch (Exception e) {
                postError(callback, -1, "Download failed: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        });
    }

    // --- Audit Logs & Client Events ---

    public void fetchAuditLogs(ApiCallback<JSONObject> callback) {
        executeJsonRequest("GET", "/api/logs", null, callback);
    }

    public void postSecurityEvent(String eventType, String severity, String fileId, String shareId, JSONObject metadata, ApiCallback<JSONObject> callback) {
        executor.execute(() -> {
            try {
                JSONObject body = new JSONObject();
                body.put("event_type", eventType);
                body.put("severity", severity != null ? severity : "INFO");
                if (fileId != null) body.put("file_id", fileId);
                if (shareId != null) body.put("share_id", shareId);
                if (metadata != null) body.put("metadata", metadata);

                executeJsonRequest("POST", "/api/logs", body, callback != null ? callback : new ApiCallback<JSONObject>() {
                    @Override public void onSuccess(JSONObject result) {}
                    @Override public void onError(int statusCode, String errorMessage) {}
                });
            } catch (Exception ignored) {
            }
        });
    }

    // --- Helper Methods ---

    private void executeJsonRequest(String method, String endpoint, JSONObject body, ApiCallback<JSONObject> callback) {
        executor.execute(() -> {
            HttpURLConnection conn = null;
            try {
                URL url = new URL(getBaseUrl() + endpoint);
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod(method);
                conn.setConnectTimeout(60000);
                conn.setReadTimeout(60000);
                conn.setRequestProperty("Content-Type", "application/json");

                String authToken = prefs.getAuthToken();
                if (authToken != null) {
                    conn.setRequestProperty("Authorization", "Bearer " + authToken);
                }

                if (body != null && (method.equals("POST") || method.equals("PUT"))) {
                    conn.setDoOutput(true);
                    DataOutputStream dos = new DataOutputStream(conn.getOutputStream());
                    dos.write(body.toString().getBytes(StandardCharsets.UTF_8));
                    dos.flush();
                    dos.close();
                }

                int statusCode = conn.getResponseCode();
                InputStream is = (statusCode >= 200 && statusCode < 300) ? conn.getInputStream() : conn.getErrorStream();
                String responseStr = readStreamToString(is);

                if (statusCode >= 200 && statusCode < 300) {
                    JSONObject json = responseStr.isEmpty() ? new JSONObject() : new JSONObject(responseStr);
                    postSuccess(callback, json);
                } else {
                    String err = parseErrorMessage(responseStr);
                    postError(callback, statusCode, err);
                }
            } catch (Exception e) {
                postError(callback, -1, "Network error: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        });
    }

    private String readStreamToString(InputStream is) {
        if (is == null) return "";
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int len;
            while ((len = is.read(buf)) != -1) {
                bos.write(buf, 0, len);
            }
            return bos.toString("UTF-8");
        } catch (Exception e) {
            return "";
        }
    }

    private String parseErrorMessage(String rawResponse) {
        try {
            JSONObject obj = new JSONObject(rawResponse);
            if (obj.has("error")) return obj.getString("error");
            if (obj.has("message")) return obj.getString("message");
        } catch (Exception ignored) {
        }
        return rawResponse.isEmpty() ? "Unknown server error" : rawResponse;
    }

    private <T> void postSuccess(ApiCallback<T> callback, T result) {
        if (callback != null) {
            mainHandler.post(() -> callback.onSuccess(result));
        }
    }

    private void postError(ApiCallback<?> callback, int statusCode, String message) {
        if (callback != null) {
            mainHandler.post(() -> callback.onError(statusCode, message));
        }
    }
}
