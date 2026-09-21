package com.securedrop.ui.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.securedrop.R;
import com.securedrop.data.model.ShareItem;

import java.util.List;

public class SharesAdapter extends RecyclerView.Adapter<SharesAdapter.ShareViewHolder> {

    public interface ShareActionListener {
        void onCopyClick(ShareItem share);
        void onRevokeClick(ShareItem share);
    }

    private final Context context;
    private final List<ShareItem> shareList;
    private final ShareActionListener listener;

    public SharesAdapter(Context context, List<ShareItem> shareList, ShareActionListener listener) {
        this.context = context;
        this.shareList = shareList;
        this.listener = listener;
    }

    @NonNull
    @Override
    public ShareViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(context).inflate(R.layout.item_share, parent, false);
        return new ShareViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ShareViewHolder holder, int position) {
        ShareItem item = shareList.get(position);
        holder.tvShareFileName.setText(item.filename != null ? item.filename : "Encrypted Document");

        String oneTimeStr = item.oneTime ? "One-time" : "Multi-download";
        long remainingMinutes = (item.expiresAt - System.currentTimeMillis()) / (60 * 1000);
        String expiryStr;
        if (remainingMinutes <= 0) {
            expiryStr = "Expired";
        } else if (remainingMinutes < 60) {
            expiryStr = "Expires in " + remainingMinutes + "m";
        } else {
            expiryStr = "Expires in " + (remainingMinutes / 60) + "h";
        }

        holder.tvShareMeta.setText(expiryStr + " • " + oneTimeStr + (item.hasPasscode ? " • Passcode" : ""));

        String tokenShort = item.token != null && item.token.length() > 12
                ? "Token: " + item.token.substring(0, 6) + "..." + item.token.substring(item.token.length() - 4)
                : "Token: " + item.token;
        holder.tvShareTokenShort.setText(tokenShort);

        String status = item.getStatusDescription();
        holder.tvShareStatusBadge.setText(status.toUpperCase());
        if ("Active".equals(status)) {
            holder.tvShareStatusBadge.setBackgroundResource(R.drawable.bg_badge_green);
            holder.tvShareStatusBadge.setTextColor(ContextCompat.getColor(context, R.color.security_green));
            holder.btnRevokeShare.setVisibility(View.VISIBLE);
        } else {
            holder.tvShareStatusBadge.setBackgroundResource(R.drawable.bg_badge_red);
            holder.tvShareStatusBadge.setTextColor(ContextCompat.getColor(context, R.color.security_red));
            holder.btnRevokeShare.setVisibility(View.GONE);
        }

        holder.btnCopyShareCode.setOnClickListener(v -> {
            if (listener != null) listener.onCopyClick(item);
        });

        holder.btnRevokeShare.setOnClickListener(v -> {
            if (listener != null) listener.onRevokeClick(item);
        });
    }

    @Override
    public int getItemCount() {
        return shareList.size();
    }

    static class ShareViewHolder extends RecyclerView.ViewHolder {
        TextView tvShareFileName, tvShareMeta, tvShareStatusBadge, tvShareTokenShort;
        MaterialButton btnCopyShareCode, btnRevokeShare;

        public ShareViewHolder(@NonNull View itemView) {
            super(itemView);
            tvShareFileName = itemView.findViewById(R.id.tvShareFileName);
            tvShareMeta = itemView.findViewById(R.id.tvShareMeta);
            tvShareStatusBadge = itemView.findViewById(R.id.tvShareStatusBadge);
            tvShareTokenShort = itemView.findViewById(R.id.tvShareTokenShort);
            btnCopyShareCode = itemView.findViewById(R.id.btnCopyShareCode);
            btnRevokeShare = itemView.findViewById(R.id.btnRevokeShare);
        }
    }
}
