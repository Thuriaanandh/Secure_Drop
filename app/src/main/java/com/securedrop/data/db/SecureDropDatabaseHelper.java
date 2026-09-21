package com.securedrop.data.db;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import com.securedrop.data.model.FileItem;
import com.securedrop.data.model.SecurityLogItem;
import com.securedrop.data.model.ShareItem;

import java.util.ArrayList;
import java.util.List;

public class SecureDropDatabaseHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "securedrop_local.db";
    private static final int DATABASE_VERSION = 1;

    private static SecureDropDatabaseHelper instance;

    public static synchronized SecureDropDatabaseHelper getInstance(Context context) {
        if (instance == null) {
            instance = new SecureDropDatabaseHelper(context.getApplicationContext());
        }
        return instance;
    }

    public SecureDropDatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE local_files (" +
                "id TEXT PRIMARY KEY, " +
                "original_name TEXT, " +
                "mime_type TEXT, " +
                "encrypted_size INTEGER, " +
                "plaintext_size INTEGER, " +
                "sha256_hash TEXT, " +
                "plaintext_sha256 TEXT, " +
                "iv_hex TEXT, " +
                "auth_tag_hex TEXT, " +
                "wrapped_key TEXT, " +
                "created_at INTEGER)");

        db.execSQL("CREATE TABLE local_shares (" +
                "id TEXT PRIMARY KEY, " +
                "file_id TEXT, " +
                "token TEXT, " +
                "composite_code TEXT, " +
                "expires_at INTEGER, " +
                "one_time INTEGER, " +
                "download_count INTEGER, " +
                "revoked INTEGER, " +
                "has_passcode INTEGER, " +
                "require_biometric INTEGER, " +
                "prevent_screenshots INTEGER, " +
                "created_at INTEGER, " +
                "filename TEXT)");

        db.execSQL("CREATE TABLE security_audit_logs (" +
                "id TEXT PRIMARY KEY, " +
                "event_type TEXT, " +
                "severity TEXT, " +
                "description TEXT, " +
                "original_name TEXT, " +
                "timestamp INTEGER)");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS local_files");
        db.execSQL("DROP TABLE IF EXISTS local_shares");
        db.execSQL("DROP TABLE IF EXISTS security_audit_logs");
        onCreate(db);
    }

    // --- Files Operations ---
    public void saveFileItem(FileItem item, String wrappedKey) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put("id", item.id);
        values.put("original_name", item.originalName);
        values.put("mime_type", item.mimeType);
        values.put("encrypted_size", item.encryptedSize);
        values.put("plaintext_size", item.plaintextSize);
        values.put("sha256_hash", item.sha256Hash);
        values.put("plaintext_sha256", item.plaintextSha256);
        values.put("iv_hex", item.ivHex);
        values.put("auth_tag_hex", item.authTagHex);
        values.put("wrapped_key", wrappedKey);
        values.put("created_at", item.createdAt);
        db.insertWithOnConflict("local_files", null, values, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public List<FileItem> getLocalFiles() {
        List<FileItem> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.rawQuery("SELECT * FROM local_files ORDER BY created_at DESC", null);
        if (cursor != null && cursor.moveToFirst()) {
            do {
                FileItem item = new FileItem(
                        cursor.getString(cursor.getColumnIndexOrThrow("id")),
                        cursor.getString(cursor.getColumnIndexOrThrow("original_name")),
                        cursor.getString(cursor.getColumnIndexOrThrow("mime_type")),
                        cursor.getLong(cursor.getColumnIndexOrThrow("encrypted_size")),
                        cursor.getLong(cursor.getColumnIndexOrThrow("plaintext_size")),
                        cursor.getString(cursor.getColumnIndexOrThrow("sha256_hash")),
                        cursor.getString(cursor.getColumnIndexOrThrow("plaintext_sha256")),
                        cursor.getString(cursor.getColumnIndexOrThrow("iv_hex")),
                        cursor.getString(cursor.getColumnIndexOrThrow("auth_tag_hex")),
                        cursor.getLong(cursor.getColumnIndexOrThrow("created_at"))
                );
                item.wrappedKey = cursor.getString(cursor.getColumnIndexOrThrow("wrapped_key"));
                list.add(item);
            } while (cursor.moveToNext());
            cursor.close();
        }
        return list;
    }

    public FileItem getFileById(String fileId) {
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.rawQuery("SELECT * FROM local_files WHERE id = ?", new String[]{fileId});
        if (cursor != null && cursor.moveToFirst()) {
            FileItem item = new FileItem(
                    cursor.getString(cursor.getColumnIndexOrThrow("id")),
                    cursor.getString(cursor.getColumnIndexOrThrow("original_name")),
                    cursor.getString(cursor.getColumnIndexOrThrow("mime_type")),
                    cursor.getLong(cursor.getColumnIndexOrThrow("encrypted_size")),
                    cursor.getLong(cursor.getColumnIndexOrThrow("plaintext_size")),
                    cursor.getString(cursor.getColumnIndexOrThrow("sha256_hash")),
                    cursor.getString(cursor.getColumnIndexOrThrow("plaintext_sha256")),
                    cursor.getString(cursor.getColumnIndexOrThrow("iv_hex")),
                    cursor.getString(cursor.getColumnIndexOrThrow("auth_tag_hex")),
                    cursor.getLong(cursor.getColumnIndexOrThrow("created_at"))
            );
            item.wrappedKey = cursor.getString(cursor.getColumnIndexOrThrow("wrapped_key"));
            cursor.close();
            return item;
        }
        if (cursor != null) cursor.close();
        return null;
    }

    // --- Shares Operations ---
    public void saveShareItem(ShareItem item) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put("id", item.id);
        values.put("file_id", item.fileId);
        values.put("token", item.token);
        values.put("composite_code", item.compositeCode);
        values.put("expires_at", item.expiresAt);
        values.put("one_time", item.oneTime ? 1 : 0);
        values.put("download_count", item.downloadCount);
        values.put("revoked", item.revoked ? 1 : 0);
        values.put("has_passcode", item.hasPasscode ? 1 : 0);
        values.put("require_biometric", item.requireBiometric ? 1 : 0);
        values.put("prevent_screenshots", item.preventScreenshots ? 1 : 0);
        values.put("created_at", item.createdAt);
        values.put("filename", item.filename);
        db.insertWithOnConflict("local_shares", null, values, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public List<ShareItem> getLocalShares() {
        List<ShareItem> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.rawQuery("SELECT * FROM local_shares ORDER BY created_at DESC", null);
        if (cursor != null && cursor.moveToFirst()) {
            do {
                ShareItem item = new ShareItem(
                        cursor.getString(cursor.getColumnIndexOrThrow("id")),
                        cursor.getString(cursor.getColumnIndexOrThrow("file_id")),
                        cursor.getString(cursor.getColumnIndexOrThrow("token")),
                        cursor.getString(cursor.getColumnIndexOrThrow("composite_code")),
                        cursor.getLong(cursor.getColumnIndexOrThrow("expires_at")),
                        cursor.getInt(cursor.getColumnIndexOrThrow("one_time")) == 1,
                        cursor.getInt(cursor.getColumnIndexOrThrow("download_count")),
                        cursor.getInt(cursor.getColumnIndexOrThrow("revoked")) == 1,
                        cursor.getInt(cursor.getColumnIndexOrThrow("has_passcode")) == 1,
                        cursor.getInt(cursor.getColumnIndexOrThrow("require_biometric")) == 1,
                        cursor.getInt(cursor.getColumnIndexOrThrow("prevent_screenshots")) == 1,
                        cursor.getLong(cursor.getColumnIndexOrThrow("created_at")),
                        cursor.getString(cursor.getColumnIndexOrThrow("filename"))
                );
                list.add(item);
            } while (cursor.moveToNext());
            cursor.close();
        }
        return list;
    }

    public void markShareRevoked(String shareId) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("revoked", 1);
        db.update("local_shares", cv, "id = ?", new String[]{shareId});
    }

    // --- Logs Operations ---
    public void insertAuditLog(String eventType, String severity, String description, String originalName) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("id", java.util.UUID.randomUUID().toString());
        cv.put("event_type", eventType);
        cv.put("severity", severity);
        cv.put("description", description);
        cv.put("original_name", originalName);
        cv.put("timestamp", System.currentTimeMillis());
        db.insert("security_audit_logs", null, cv);
    }

    public List<SecurityLogItem> getAuditLogs() {
        List<SecurityLogItem> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.rawQuery("SELECT * FROM security_audit_logs ORDER BY timestamp DESC LIMIT 100", null);
        if (cursor != null && cursor.moveToFirst()) {
            do {
                list.add(new SecurityLogItem(
                        cursor.getString(cursor.getColumnIndexOrThrow("id")),
                        cursor.getString(cursor.getColumnIndexOrThrow("event_type")),
                        cursor.getString(cursor.getColumnIndexOrThrow("severity")),
                        cursor.getString(cursor.getColumnIndexOrThrow("description")),
                        cursor.getString(cursor.getColumnIndexOrThrow("original_name")),
                        cursor.getLong(cursor.getColumnIndexOrThrow("timestamp"))
                ));
            } while (cursor.moveToNext());
            cursor.close();
        }
        return list;
    }
}
