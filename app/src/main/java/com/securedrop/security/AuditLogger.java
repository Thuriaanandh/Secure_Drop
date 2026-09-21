package com.securedrop.security;

import android.content.Context;

import com.securedrop.data.db.SecureDropDatabaseHelper;
import com.securedrop.network.ApiClient;

import org.json.JSONObject;

public class AuditLogger {

    public static void logEvent(Context context, String eventType, String severity, String description, String originalName) {
        // 1. Record in local SQLite database
        SecureDropDatabaseHelper.getInstance(context).insertAuditLog(eventType, severity, description, originalName);

        // 2. Dispatch to backend if reachable
        try {
            JSONObject metadata = new JSONObject();
            metadata.put("description", description);
            metadata.put("original_name", originalName);

            ApiClient.getInstance(context).postSecurityEvent(eventType, severity, null, null, metadata, null);
        } catch (Exception ignored) {
        }
    }
}
