package com.securedrop.ui.audit;

import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.securedrop.R;
import com.securedrop.data.db.SecureDropDatabaseHelper;
import com.securedrop.data.model.SecurityLogItem;
import com.securedrop.network.ApiClient;
import com.securedrop.ui.adapter.AuditLogsAdapter;
import com.securedrop.ui.base.BaseActivity;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class AccessLogsActivity extends BaseActivity {

    private RecyclerView rvAccessLogs;
    private TextView tvEmptyLogs;
    private AuditLogsAdapter adapter;
    private final List<SecurityLogItem> logList = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_access_logs);

        rvAccessLogs = findViewById(R.id.rvAccessLogs);
        tvEmptyLogs = findViewById(R.id.tvEmptyLogs);

        findViewById(R.id.btnBack).setOnClickListener(v -> finish());
        findViewById(R.id.btnRefreshLogs).setOnClickListener(v -> syncLogsFromBackend());

        rvAccessLogs.setLayoutManager(new LinearLayoutManager(this));
        adapter = new AuditLogsAdapter(this, logList);
        rvAccessLogs.setAdapter(adapter);

        loadLocalLogs();
        syncLogsFromBackend();
    }

    private void loadLocalLogs() {
        logList.clear();
        logList.addAll(SecureDropDatabaseHelper.getInstance(this).getAuditLogs());
        adapter.notifyDataSetChanged();
        tvEmptyLogs.setVisibility(logList.isEmpty() ? View.VISIBLE : View.GONE);
    }

    private void syncLogsFromBackend() {
        ApiClient.getInstance(this).fetchAuditLogs(new ApiClient.ApiCallback<JSONObject>() {
            @Override
            public void onSuccess(JSONObject result) {
                try {
                    JSONArray logsArray = result.getJSONArray("logs");
                    SecureDropDatabaseHelper db = SecureDropDatabaseHelper.getInstance(AccessLogsActivity.this);

                    for (int i = 0; i < logsArray.length(); i++) {
                        JSONObject log = logsArray.getJSONObject(i);
                        String eventType = log.getString("event_type");
                        String severity = log.optString("severity", "INFO");
                        String originalName = log.optString("original_name", "");
                        String desc = eventType + " event";
                        if (log.has("metadata_json")) {
                            desc = log.getString("metadata_json");
                        }
                        db.insertAuditLog(eventType, severity, desc, originalName);
                    }

                    loadLocalLogs();
                    Toast.makeText(AccessLogsActivity.this, "Audit logs synced from server", Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    loadLocalLogs();
                }
            }

            @Override
            public void onError(int statusCode, String errorMessage) {
                // If offline or network error, local logs are still shown
                loadLocalLogs();
            }
        });
    }
}
