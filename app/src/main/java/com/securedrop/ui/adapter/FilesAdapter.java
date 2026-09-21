package com.securedrop.ui.adapter;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.securedrop.R;
import com.securedrop.data.model.FileItem;

import java.util.List;

public class FilesAdapter extends RecyclerView.Adapter<FilesAdapter.FileViewHolder> {

    public interface FileClickListener {
        void onFileClick(FileItem file);
        void onShareClick(FileItem file);
    }

    private final Context context;
    private final List<FileItem> fileList;
    private final FileClickListener listener;

    public FilesAdapter(Context context, List<FileItem> fileList, FileClickListener listener) {
        this.context = context;
        this.fileList = fileList;
        this.listener = listener;
    }

    @NonNull
    @Override
    public FileViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(context).inflate(R.layout.item_file, parent, false);
        return new FileViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull FileViewHolder holder, int position) {
        FileItem item = fileList.get(position);
        holder.tvFileName.setText(item.originalName);
        holder.tvFileSize.setText(item.getFormattedSize() + " • Encrypted (AES-256-GCM)");

        String sha = item.sha256Hash != null && item.sha256Hash.length() > 16
                ? "SHA-256: " + item.sha256Hash.substring(0, 8) + "..." + item.sha256Hash.substring(item.sha256Hash.length() - 8)
                : "SHA-256: " + item.sha256Hash;
        holder.tvFileSha.setText(sha);

        holder.itemView.setOnClickListener(v -> {
            if (listener != null) listener.onFileClick(item);
        });

        holder.btnShareFile.setOnClickListener(v -> {
            if (listener != null) listener.onShareClick(item);
        });
    }

    @Override
    public int getItemCount() {
        return fileList.size();
    }

    static class FileViewHolder extends RecyclerView.ViewHolder {
        TextView tvFileName, tvFileSize, tvFileSha, tvFileBadge;
        MaterialButton btnShareFile;

        public FileViewHolder(@NonNull View itemView) {
            super(itemView);
            tvFileName = itemView.findViewById(R.id.tvFileName);
            tvFileSize = itemView.findViewById(R.id.tvFileSize);
            tvFileSha = itemView.findViewById(R.id.tvFileSha);
            tvFileBadge = itemView.findViewById(R.id.tvFileBadge);
            btnShareFile = itemView.findViewById(R.id.btnShareFile);
        }
    }
}
