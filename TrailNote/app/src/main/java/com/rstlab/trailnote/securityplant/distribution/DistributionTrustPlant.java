package com.rstlab.trailnote.securityplant.distribution;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.rstlab.trailnote.BuildConfig;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * Third trust boundary for installed APKs.
 *
 * Production mode is fail-closed and requires a compile-time signing certificate pin.
 * It also maintains a Keystore-HMAC sealed anti-rollback/same-version-binary state.
 * Diagnostic builds intentionally live in a separate package/signing domain and never
 * claim production trust.
 */
public final class DistributionTrustPlant {
    private static final String CANONICAL_PACKAGE = "com.rstlab.trailnote";
    private static final String PREF = "trailnote_distribution_trust_v1";
    private static final String KEY_VERSION = "max_version";
    private static final String KEY_APK = "apk_sha256";
    private static final String KEY_SIGNER = "signer_sha256";
    private static final String KEY_MAC = "state_mac";
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String STATE_KEY_ALIAS = "trailnote.distribution.state.hmac.v1";
    private static final long CACHE_MS = 3_000L;

    public static final class Report {
        public final boolean production;
        public final boolean trusted;
        public final boolean critical;
        public final String level;
        public final String currentSignerSha256;
        public final String apkSha256;
        public final long versionCode;
        public final List<String> signals;

        Report(boolean production, boolean trusted, boolean critical, String level,
               String currentSignerSha256, String apkSha256, long versionCode,
               List<String> signals) {
            this.production = production;
            this.trusted = trusted;
            this.critical = critical;
            this.level = level;
            this.currentSignerSha256 = currentSignerSha256;
            this.apkSha256 = apkSha256;
            this.versionCode = versionCode;
            this.signals = Collections.unmodifiableList(signals);
        }

        public String compact() {
            return "DistributionTrust " + level + " signer=" + shortHash(currentSignerSha256)
                    + " apk=" + shortHash(apkSha256) + " v=" + versionCode;
        }

        private static String shortHash(String value) {
            if (value == null || value.isEmpty()) return "n/a";
            return value.length() <= 12 ? value : value.substring(0, 12);
        }
    }

    private final Context context;
    private final SharedPreferences prefs;
    private Report cached;
    private long cachedAt;

    public DistributionTrustPlant(Context context) {
        this.context = context.getApplicationContext();
        this.prefs = this.context.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    public synchronized Report verify() {
        long now = System.currentTimeMillis();
        if (cached != null && now - cachedAt < CACHE_MS) return cached;
        cached = evaluate();
        cachedAt = now;
        return cached;
    }

    private Report evaluate() {
        final boolean production = "production".equalsIgnoreCase(BuildConfig.DISTRIBUTION_TRUST_MODE);
        final List<String> signals = new ArrayList<>();
        boolean critical = false;
        boolean signerTrusted = false;
        String currentSigner = "";
        String apkHash = "";
        long version = -1L;

        try {
            if (!BuildConfig.APPLICATION_ID.equals(context.getPackageName())) {
                critical = true;
                signals.add("runtime-package-id-mismatch");
            }
            if (production && !CANONICAL_PACKAGE.equals(context.getPackageName())) {
                critical = true;
                signals.add("production-package-domain-mismatch");
            }
            if (!production) signals.add("diagnostic-signing-domain");

            boolean debuggable = (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
            if (production && debuggable) {
                critical = true;
                signals.add("production-debuggable-flag");
            }

            SigningSnapshot signing = signingSnapshot();
            currentSigner = signing.currentSigner;
            if (signing.multipleSigners && production) {
                critical = true;
                signals.add("unexpected-multiple-signers");
            }

            Set<String> trustedPins = configuredPins();
            if (production) {
                if (trustedPins.isEmpty()) {
                    critical = true;
                    signals.add("production-signing-pin-missing");
                } else {
                    for (String pin : trustedPins) {
                        if (signing.lineage.contains(pin)) {
                            signerTrusted = true;
                            break;
                        }
                    }
                    if (!signerTrusted) {
                        critical = true;
                        signals.add("production-signing-lineage-rejected");
                    }
                }
            } else {
                signerTrusted = true;
            }

            version = versionCode();
            apkHash = fileSha256(context.getApplicationInfo().sourceDir);

            if (prefs.contains(KEY_MAC)) {
                long oldVersion = prefs.getLong(KEY_VERSION, -1L);
                String oldApk = prefs.getString(KEY_APK, "");
                String oldSigner = prefs.getString(KEY_SIGNER, "");
                String storedMac = prefs.getString(KEY_MAC, "");
                String expectedMac = stateMac(oldVersion, oldApk, oldSigner);
                if (!constantTimeEquals(storedMac, expectedMac)) {
                    signals.add("sealed-distribution-state-tampered");
                    if (production) critical = true;
                } else {
                    if (version < oldVersion) {
                        signals.add("version-rollback-detected");
                        if (production) critical = true;
                    }
                    if (version == oldVersion && !constantTimeEquals(oldApk, apkHash)) {
                        signals.add("same-version-binary-substitution");
                        if (production) critical = true;
                    }
                    if (production && !oldSigner.isEmpty() && !signing.lineage.contains(oldSigner)) {
                        critical = true;
                        signals.add("signing-rotation-lineage-break");
                    }
                }
            }

            if (!critical && signerTrusted) {
                long oldVersion = prefs.getLong(KEY_VERSION, -1L);
                if (version >= oldVersion) {
                    String mac = stateMac(version, apkHash, currentSigner);
                    prefs.edit()
                            .putLong(KEY_VERSION, version)
                            .putString(KEY_APK, apkHash)
                            .putString(KEY_SIGNER, currentSigner)
                            .putString(KEY_MAC, mac)
                            .commit();
                }
            }
        } catch (Exception e) {
            signals.add("distribution-verifier-error:" + e.getClass().getSimpleName());
            if (production) critical = true;
        }

        String level;
        boolean trusted;
        if (critical) {
            level = "BLOCKED";
            trusted = false;
        } else if (production && signerTrusted) {
            level = "PRODUCTION-TRUSTED";
            trusted = true;
        } else {
            level = "DIAGNOSTIC";
            trusted = false;
        }
        return new Report(production, trusted, critical, level, currentSigner, apkHash, version, signals);
    }

    private SigningSnapshot signingSnapshot() throws Exception {
        PackageManager pm = context.getPackageManager();
        PackageInfo info;
        Signature[] current;
        Signature[] history;
        boolean multiple = false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
            if (info.signingInfo == null) throw new IllegalStateException("No signing info");
            multiple = info.signingInfo.hasMultipleSigners();
            current = info.signingInfo.getApkContentsSigners();
            history = multiple ? current : info.signingInfo.getSigningCertificateHistory();
        } else {
            info = pm.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            current = info.signatures;
            history = current;
        }
        if (current == null || current.length == 0) throw new IllegalStateException("No current signer");
        Set<String> lineage = new LinkedHashSet<>();
        if (history != null) {
            for (Signature signature : history) lineage.add(signatureSha256(signature));
        }
        String currentDigest = signatureSha256(current[0]);
        lineage.add(currentDigest);
        return new SigningSnapshot(currentDigest, lineage, multiple);
    }

    private Set<String> configuredPins() {
        Set<String> pins = new LinkedHashSet<>();
        String raw = BuildConfig.TRUSTED_SIGNING_CERT_SHA256 == null ? "" : BuildConfig.TRUSTED_SIGNING_CERT_SHA256;
        for (String token : raw.split("[;,\\s]+")) {
            String normalized = normalizeHex(token);
            if (normalized.length() == 64) pins.add(normalized);
        }
        return pins;
    }

    private long versionCode() throws Exception {
        PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) return info.getLongVersionCode();
        return info.versionCode;
    }

    private String stateMac(long version, String apkHash, String signerHash) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(getOrCreateStateKey());
        String payload = version + "|" + safe(apkHash) + "|" + safe(signerHash) + "|distribution-state-v1";
        return Base64.encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
    }

    private SecretKey getOrCreateStateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(STATE_KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(
                STATE_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }

    private static String signatureSha256(Signature signature) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return hex(digest.digest(signature.toByteArray()));
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

    private static String normalizeHex(String value) {
        if (value == null) return "";
        return value.replaceAll("[^0-9A-Fa-f]", "").toLowerCase(Locale.ROOT);
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        return sb.toString();
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static final class SigningSnapshot {
        final String currentSigner;
        final Set<String> lineage;
        final boolean multipleSigners;

        SigningSnapshot(String currentSigner, Set<String> lineage, boolean multipleSigners) {
            this.currentSigner = currentSigner;
            this.lineage = lineage;
            this.multipleSigners = multipleSigners;
        }
    }
}
