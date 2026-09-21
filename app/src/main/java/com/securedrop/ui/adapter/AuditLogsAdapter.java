package com.securedrop.ui.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.securedrop.R;
import com.securedrop.data.model.SecurityLogItem;

import java.util.List;

public class AuditLogsAdapter extends RecyclerView.Adapter<AuditLogsAdapter.LogViewHolder> {

    private final Context context;
    private final List<SecurityLogItem> logList;

    public AuditLogsAdapter(Context context, List<SecurityLogItem> logList) {
        this.context = context;
        this.logList = logList;
    }

    @NonNull
    @Override
    public LogViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(context).inflate(R.layout.item_audit_log, parent, false);
        return new LogViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull LogViewHolder holder, int position) {
        SecurityLogItem item = logList.get(position);
        holder.tvLogEventType.setText(item.eventType);
        holder.tvLogDescription.setText(item.description);
        holder.tvLogTimestamp.setText(item.getFormattedTime());
        holder.tvLogSeverityBadge.setText(item.severity);

        if ("CRITICAL".equalsIgnoreCase(item.severity)) {
            holder.ivLogSeverity.setImageResource(R.drawable.ic_warning);
            holder.ivLogSeverity.setBackgroundResource(R.drawable.bg_badge_red);
            holder.ivLogSeverity.setColorFilter(ContextCompat.getColor(context, R.color.security_red));
            holder.tvLogSeverityBadge.setBackgroundResource(R.drawable.bg_badge_red);
            holder.tvLogSeverityBadge.setTextColor(ContextCompat.getColor(context, R.color.security_red));
        } else if ("WARNING".equalsIgnoreCase(item.severity)) {
            holder.ivLogSeverity.setImageResource(R.drawable.ic_warning);
            holder.ivLogSeverity.setBackgroundResource(R.drawable.bg_badge_amber);
            holder.ivLogSeverity.setColorFilter(ContextCompat.getColor(context, R.color.security_amber));
            holder.tvLogSeverityBadge.setBackgroundResource(R.drawable.bg_badge_amber);
            holder.tvLogSeverityBadge.setTextColor(ContextCompat.getColor(context, R.color.security_amber));
        } else {
            holder.ivLogSeverity.setImageResource(R.drawable.ic_shield_check);
            holder.ivLogSeverity.setBackgroundResource(R.drawable.bg_badge_green);
            holder.ivLogSeverity.setColorFilter(ContextCompat.getColor(context, R.color.security_green));
            holder.tvLogSeverityBadge.setBackgroundResource(R.drawable.bg_badge_green);
            holder.tvLogSeverityBadge.setTextColor(ContextCompat.getColor(context, R.color.security_green));
        }
    }

    @Override
    public int getItemCount() {
        return logList.size();
    }

    static class LogViewHolder extends RecyclerView.ViewHolder {
        ImageView ivLogSeverity;
        TextView tvLogEventType, tvLogSeverityBadge, tvLogDescription, tvLogTimestamp;

        public LogViewHolder(@NonNull View itemView) {
            super(itemView);
            ivLogSeverity = itemView.findViewById(R.id.ivLogSeverity);
            tvLogEventType = itemView.findViewById(R.id.tvLogEventType);
            tvLogSeverityBadge = itemView.findViewById(R.id.tvLogSeverityBadge);
            tvLogDescription = itemView.findViewById(R.id.tvLogDescription);
            tvLogTimestamp = itemView.findViewById(R.id.tvLogTimestamp);
        }
    }
}
