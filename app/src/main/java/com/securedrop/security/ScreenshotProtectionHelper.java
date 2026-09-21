package com.securedrop.security;

import android.app.Activity;
import android.os.Build;
import android.view.WindowManager;
import android.widget.Toast;

public class ScreenshotProtectionHelper {

    public interface ScreenshotListener {
        void onScreenshotDetected();
    }

    private Activity.ScreenCaptureCallback screenCaptureCallback;

    public void applyProtection(Activity activity, boolean enabled, ScreenshotListener listener) {
        if (activity == null || activity.getWindow() == null) return;

        if (enabled) {
            // Apply FLAG_SECURE: blocks screenshots and screen recording at window manager level
            activity.getWindow().setFlags(
                    WindowManager.LayoutParams.FLAG_SECURE,
                    WindowManager.LayoutParams.FLAG_SECURE
            );

            // Android 14+ (API 34+) screenshot detection callback
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                try {
                    if (screenCaptureCallback == null) {
                        screenCaptureCallback = new Activity.ScreenCaptureCallback() {
                            @Override
                            public void onScreenCaptured() {
                                activity.runOnUiThread(() -> {
                                    Toast.makeText(activity, "⚠️ Security Alert: Screenshot attempt detected on secure screen.", Toast.LENGTH_LONG).show();
                                    if (listener != null) {
                                        listener.onScreenshotDetected();
                                    }
                                });
                            }
                        };
                        activity.registerScreenCaptureCallback(activity.getMainExecutor(), screenCaptureCallback);
                    }
                } catch (Exception e) {
                    // Graceful fallback for custom OEM forks
                    e.printStackTrace();
                }
            }
        } else {
            activity.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
            removeCallback(activity);
        }
    }

    public void removeCallback(Activity activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE && screenCaptureCallback != null && activity != null) {
            try {
                activity.unregisterScreenCaptureCallback(screenCaptureCallback);
                screenCaptureCallback = null;
            } catch (Exception ignored) {
            }
        }
    }
}
