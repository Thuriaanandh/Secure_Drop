package com.securedrop.data.model;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class SecurityLogItem {
    public final String id;
    public final String eventType;
    public final String severity; // INFO, WARNING, CRITICAL
    public final String description;
    public final String originalName;
    public final long timestamp;

    public SecurityLogItem(String id, String eventType, String severity, String description, String originalName, long timestamp) {
        this.id = id;
        this.eventType = eventType;
        this.severity = severity;
        this.description = description;
        this.originalName = originalName;
        this.timestamp = timestamp;
    }

    public String getFormattedTime() {
        SimpleDateFormat sdf = new SimpleDateFormat("MMM dd, yyyy  HH:mm:ss", Locale.getDefault());
        return sdf.format(new Date(timestamp));
    }
}
