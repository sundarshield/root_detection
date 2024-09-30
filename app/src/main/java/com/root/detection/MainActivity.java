package com.root.detection;

import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "RootDetection";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        RootDetectionResult result = detectRoot();
        showRootStatusDialog(result);
    }

    private static class RootDetectionResult {
        boolean isRooted;
        List<String> detectedMethods;

        RootDetectionResult(boolean isRooted, List<String> detectedMethods) {
            this.isRooted = isRooted;
            this.detectedMethods = detectedMethods;
        }
    }

    private RootDetectionResult detectRoot() {
        List<String> detectedMethods = new ArrayList<>();
        boolean isRooted = false;

        if (checkForSuperuserApps()) {
            isRooted = true;
            detectedMethods.add("Superuser apps detected");
        }
        if (checkLogcatForRoot()) {
            isRooted = true;
            detectedMethods.add("magisk or zygisk found in logcat -d");
        }
        if (checkForSuBinary()) {
            isRooted = true;
            detectedMethods.add("su binary found");
        }
        if (checkForBuildTags()) {
            isRooted = true;
            detectedMethods.add("Build tags indicate root");
        }
        if (checkForRootManagementApps()) {
            isRooted = true;
            detectedMethods.add("Root management apps installed");
        }
        if (checkSelfStatus()) {
            isRooted = true;
            detectedMethods.add("Self status indicates root");
        }
        if (checkForDangerousProps()) {
            isRooted = true;
            detectedMethods.add("Dangerous properties detected");
        }
        if (checkForUnusualPermissions()) {
            isRooted = true;
            detectedMethods.add("Unusual permissions granted");
        }

        return new RootDetectionResult(isRooted, detectedMethods);
    }

    private boolean checkForSuperuserApps() {
        String[] suApps = {"/system/app/SuperSU/SuperSU.apk", "/system/xbin/su", "/system/bin/su"};
        for (String app : suApps) {
            if (new File(app).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkForSuBinary() {
        String[] paths = {"/sbin/su", "/system/sd/xbin/su", "/system/bin/su", "/system/xbin/su"};
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkForBuildTags() {
        return android.os.Build.TAGS != null && android.os.Build.TAGS.contains("test-keys");
    }

    private boolean checkForRootManagementApps() {
        String[] rootApps = {"com.noshufou.android.su", "eu.chainfire.supersu", "com.koushikdutta.superuser"};
        for (String app : rootApps) {
            try {
                getPackageManager().getPackageInfo(app, 0);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // App not found, continue checking
            }
        }
        return false;
    }

    private boolean checkSelfStatus() {
        String statusFile = "/proc/self/status";
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(statusFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
        } catch (IOException e) {
            Log.e(TAG, "Error reading status file", e);
        }

        return sb.toString().contains("Uid:\t0");
    }
    private boolean checkLogcatForRoot() {
        try {
            // Execute the logcat command and filter for "Magisk" and "Zygisk"
            Process process = Runtime.getRuntime().exec("logcat -d | grep -e magisk -e zygisk");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            // Read the output of the command
            while ((line = reader.readLine()) != null) {
                // If either keyword is found in the output, the device is likely rooted
                if (line.toLowerCase().contains("magisk") || line.toLowerCase().contains("zygisk")) {
                    return true; // Device is rooted
                }
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false; // Device is not rooted
    }

    private boolean checkForDangerousProps() {
        String[] props = {"ro.debuggable", "ro.secure", "ro.build.tags"};
        for (String prop : props) {
            String value = getProp(prop);
            if ("1".equals(value) || value.contains("test-keys")) {
                return true;
            }
        }
        return false;
    }

    private String getProp(String propName) {
        String propValue = "";
        try {
            Process process = Runtime.getRuntime().exec("getprop " + propName);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            propValue = reader.readLine();
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return propValue;
    }

    private boolean checkForUnusualPermissions() {
        int permission = checkSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE");
        return permission == PackageManager.PERMISSION_GRANTED;
    }

    private void showRootStatusDialog(RootDetectionResult result) {
        StringBuilder message = new StringBuilder(result.isRooted
                ? "Your device is rooted!\n\nDetected Methods:\n"
                : "Your device is not rooted.\n\n");

        if (result.isRooted) {
            for (String method : result.detectedMethods) {
                message.append("- ").append(method).append("\n");
            }
        }

        new AlertDialog.Builder(this)
                .setTitle("Root Detection")
                .setMessage(message.toString())
                .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                })
                .setIcon(result.isRooted ? android.R.drawable.ic_dialog_alert : android.R.drawable.ic_dialog_info)
                .show();
    }
}
