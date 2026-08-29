package com.rstlab.trailnote.securityplant;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Debug;

import com.rstlab.trailnote.BuildConfig;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

final class ThreatScanner {
    private static final String PREF = "trailnote_securityplant_integrity_v1";
    private static final String KEY_CERT = "signing_cert_sha256";
    private static final String KEY_APK_VERSION = "apk_version";
    private static final String KEY_APK_HASH = "apk_sha256";

    static final class Report {
        final int score;
        final boolean criticalTamper;
        final List<String> signals;

        Report(int score, boolean criticalTamper, List<String> signals) {
            this.score = Math.min(100, Math.max(0, score));
            this.criticalTamper = criticalTamper;
            this.signals = Collections.unmodifiableList(signals);
        }

        String level() {
            if (criticalTamper || score >= 95) return "CRITICAL";
            if (score >= 70) return "HIGH";
            if (score >= 45) return "ELEVATED";
            if (score >= 20) return "GUARDED";
            return "NORMAL";
        }
    }

    private final Context context;
    private final SharedPreferences integrityPrefs;
    private boolean staticIntegrityChecked;
    private int staticScore;
    private boolean staticCritical;
    private final List<String> staticSignals = new ArrayList<>();

    ThreatScanner(Context context) {
        this.context = context.getApplicationContext();
        this.integrityPrefs = context.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    synchronized Report scan() {
        int score = 0;
        boolean critical = false;
        List<String> signals = new ArrayList<>();

        if (!staticIntegrityChecked) {
            runStaticIntegrityChecks();
            staticIntegrityChecked = true;
        }
        score += staticScore;
        critical |= staticCritical;
        signals.addAll(staticSignals);

        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            score += 55;
            signals.add("debugger-attached");
        }
        int tracerPid = readTracerPid();
        if (tracerPid > 0) {
            score += 50;
            signals.add("tracerpid=" + tracerPid);
        }

        boolean appDebuggable = (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        if (appDebuggable) {
            score += BuildConfig.DEBUG ? 8 : 45;
            signals.add(BuildConfig.DEBUG ? "debug-build" : "unexpected-debuggable-flag");
        }

        if (looksRooted()) {
            score += 28;
            signals.add("root-artifacts");
        }
        if (Build.TAGS != null && Build.TAGS.contains("test-keys")) {
            score += 10;
            signals.add("test-keys-build");
        }
        if (selinuxNotEnforcing()) {
            score += 32;
            signals.add("selinux-not-enforced");
        }

        score += hookFrameworkScore(signals);

        if (looksLikeEmulator()) {
            score += 6;
            signals.add("emulator-like-environment");
        }

        return new Report(score, critical, signals);
    }

    private void runStaticIntegrityChecks() {
        try {
            String cert = signingCertSha256();
            String stored = integrityPrefs.getString(KEY_CERT, null);
            if (stored == null) {
                integrityPrefs.edit().putString(KEY_CERT, cert).commit();
            } else if (!constantTimeStringEquals(stored, cert)) {
                staticScore += 100;
                staticCritical = true;
                staticSignals.add("signing-certificate-changed");
            }
        } catch (Exception e) {
            staticScore += 18;
            staticSignals.add("signing-integrity-check-unavailable");
        }

        try {
            long version = versionCode();
            String apkHash = fileSha256(context.getApplicationInfo().sourceDir);
            long oldVersion = integrityPrefs.getLong(KEY_APK_VERSION, -1L);
            String oldHash = integrityPrefs.getString(KEY_APK_HASH, null);
            if (oldVersion == version && oldHash != null && !constantTimeStringEquals(oldHash, apkHash)) {
                staticScore += 100;
                staticCritical = true;
                staticSignals.add("apk-bytes-changed-without-version-change");
            } else if (oldVersion != version || oldHash == null) {
                integrityPrefs.edit().putLong(KEY_APK_VERSION, version).putString(KEY_APK_HASH, apkHash).commit();
            }
        } catch (Exception e) {
            staticScore += 12;
            staticSignals.add("apk-integrity-check-unavailable");
        }
    }

    private int hookFrameworkScore(List<String> signals) {
        int score = 0;
        String maps = readProcMaps().toLowerCase(Locale.ROOT);
        if (containsAny(maps, "frida", "gum-js-loop", "libsubstrate", "xposed", "edxp", "lsposed", "zygisk")) {
            score += 70;
            signals.add("instrumentation-or-hook-library");
        }
        if (classExists("de.robv.android.xposed.XposedBridge") || classExists("com.saurik.substrate.MS$2")) {
            score += 65;
            signals.add("hook-framework-class");
        }
        return score;
    }

    private boolean looksRooted() {
        String[] paths = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
                "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
                "/data/adb/magisk", "/data/adb/modules", "/data/local/su"
        };
        for (String path : paths) {
            try {
                if (new File(path).exists()) return true;
            } catch (SecurityException ignored) {
            }
        }
        return false;
    }

    private boolean selinuxNotEnforcing() {
        File enforce = new File("/sys/fs/selinux/enforce");
        if (!enforce.exists()) return false;
        try (BufferedReader reader = new BufferedReader(new FileReader(enforce))) {
            String value = reader.readLine();
            return value != null && !"1".equals(value.trim());
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean looksLikeEmulator() {
        String fp = safe(Build.FINGERPRINT).toLowerCase(Locale.ROOT);
        String model = safe(Build.MODEL).toLowerCase(Locale.ROOT);
        String product = safe(Build.PRODUCT).toLowerCase(Locale.ROOT);
        String hardware = safe(Build.HARDWARE).toLowerCase(Locale.ROOT);
        return fp.startsWith("generic") || fp.contains("emulator") || fp.contains("unknown")
                || model.contains("google_sdk") || model.contains("emulator") || model.contains("android sdk built for")
                || product.contains("sdk") || product.contains("emulator")
                || hardware.contains("goldfish") || hardware.contains("ranchu");
    }

    private int readTracerPid() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    return Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
                }
            }
        } catch (Exception ignored) {
        }
        return 0;
    }

    private String readProcMaps() {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            int lines = 0;
            while ((line = reader.readLine()) != null && lines++ < 6000) sb.append(line).append('\n');
        } catch (Exception ignored) {
        }
        return sb.toString();
    }

    private boolean classExists(String name) {
        try {
            Class.forName(name, false, context.getClassLoader());
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private String signingCertSha256() throws Exception {
        PackageManager pm = context.getPackageManager();
        PackageInfo info;
        Signature[] signatures;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
            if (info.signingInfo == null) throw new IllegalStateException("No signing info");
            signatures = info.signingInfo.hasMultipleSigners()
                    ? info.signingInfo.getApkContentsSigners()
                    : info.signingInfo.getSigningCertificateHistory();
        } else {
            info = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            signatures = info.signatures;
        }
        if (signatures == null || signatures.length == 0) throw new IllegalStateException("No signing certificate");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return hex(digest.digest(signatures[0].toByteArray()));
    }

    private long versionCode() throws Exception {
        PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) return info.getLongVersionCode();
        return info.versionCode;
    }

    private static String fileSha256(String path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[64 * 1024];
        try (InputStream in = new FileInputStream(path)) {
            int n;
            while ((n = in.read(buffer)) != -1) digest.update(buffer, 0, n);
        }
        return hex(digest.digest());
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        return sb.toString();
    }

    private static boolean constantTimeStringEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] x = a.getBytes();
        byte[] y = b.getBytes();
        if (x.length != y.length) return false;
        int diff = 0;
        for (int i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
        return diff == 0;
    }

    private static boolean containsAny(String haystack, String... needles) {
        for (String n : needles) if (haystack.contains(n)) return true;
        return false;
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
