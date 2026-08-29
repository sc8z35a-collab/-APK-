package com.rstlab.trailnote.securityplant;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * Independent fourth distribution/runtime boundary.
 *
 * Instead of trusting only one whole-APK digest, this plant fingerprints executable
 * DEX files, AndroidManifest.xml, resources.arsc and native libraries separately.
 * The per-version component map is sealed with a distinct Android Keystore HMAC key.
 * Production first-use authenticity is anchored by DistributionTrustPlant's pinned
 * signing identity; subsequent same-version component substitution fails closed.
 */
final class ComponentIntegrityPlant {
    private static final String PREF = "trailnote_component_integrity_v1";
    private static final String KEY_VERSION = "version";
    private static final String KEY_MAP = "component_map";
    private static final String KEY_MAC = "component_mac";
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String HMAC_ALIAS = "trailnote.component.integrity.hmac.v1";
    private static final long CACHE_MS = 5_000L;

    static final class Report {
        final boolean critical;
        final boolean baselineCreated;
        final int componentCount;
        final String mapSha256;
        final List<String> signals;

        Report(boolean critical, boolean baselineCreated, int componentCount,
               String mapSha256, List<String> signals) {
            this.critical = critical;
            this.baselineCreated = baselineCreated;
            this.componentCount = componentCount;
            this.mapSha256 = mapSha256;
            this.signals = Collections.unmodifiableList(signals);
        }

        String compact() {
            return (critical ? "BLOCKED" : "OK") + " components=" + componentCount
                    + " map=" + shortHash(mapSha256);
        }
    }

    private final Context context;
    private final SharedPreferences prefs;
    private Report cached;
    private long cachedAt;

    ComponentIntegrityPlant(Context context) {
        this.context = context.getApplicationContext();
        this.prefs = this.context.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    synchronized Report verify(boolean distributionTrusted) {
        long now = System.currentTimeMillis();
        if (cached != null && now - cachedAt < CACHE_MS) return cached;
        cached = evaluate(distributionTrusted);
        cachedAt = now;
        return cached;
    }

    private Report evaluate(boolean distributionTrusted) {
        List<String> signals = new ArrayList<>();
        try {
            long version = versionCode();
            ComponentMap map = buildComponentMap();
            String mapDigest = sha256(map.canonical.getBytes(StandardCharsets.UTF_8));
            boolean baselineCreated = false;
            boolean critical = false;

            if (prefs.contains(KEY_MAC)) {
                long storedVersion = prefs.getLong(KEY_VERSION, -1L);
                String storedMap = prefs.getString(KEY_MAP, "");
                String storedMac = prefs.getString(KEY_MAC, "");
                if (!constantTimeEquals(storedMac, mac(storedVersion, storedMap))) {
                    signals.add("component-baseline-seal-tampered");
                    critical = distributionTrusted;
                } else if (storedVersion == version && !constantTimeEquals(storedMap, map.canonical)) {
                    signals.add("same-version-component-substitution");
                    critical = true;
                } else if (storedVersion > version) {
                    signals.add("component-version-rollback");
                    critical = distributionTrusted;
                }
            }

            if (!critical) {
                long oldVersion = prefs.getLong(KEY_VERSION, -1L);
                if (!prefs.contains(KEY_MAC) || version > oldVersion) {
                    String seal = mac(version, map.canonical);
                    if (!prefs.edit().putLong(KEY_VERSION, version)
                            .putString(KEY_MAP, map.canonical)
                            .putString(KEY_MAC, seal).commit()) {
                        signals.add("component-baseline-commit-failed");
                        critical = distributionTrusted;
                    } else {
                        baselineCreated = true;
                        signals.add(distributionTrusted ? "production-component-baseline-sealed" : "diagnostic-component-baseline-sealed");
                    }
                }
            }
            if (map.componentCount < 3) {
                signals.add("unexpectedly-small-apk-component-set");
                if (distributionTrusted) critical = true;
            }
            return new Report(critical, baselineCreated, map.componentCount, mapDigest, signals);
        } catch (Exception e) {
            signals.add("component-integrity-error:" + e.getClass().getSimpleName());
            return new Report(distributionTrusted, false, 0, "", signals);
        }
    }

    private ComponentMap buildComponentMap() throws Exception {
        List<String> rows = new ArrayList<>();
        int count = 0;
        try (ZipFile zip = new ZipFile(context.getApplicationInfo().sourceDir)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || !securityRelevant(entry.getName())) continue;
                rows.add(entry.getName() + "=" + hashEntry(zip, entry));
                count++;
            }
        }
        rows.sort(Comparator.naturalOrder());
        StringBuilder canonical = new StringBuilder();
        for (String row : rows) canonical.append(row).append('\n');
        return new ComponentMap(canonical.toString(), count);
    }

    private static boolean securityRelevant(String name) {
        if ("AndroidManifest.xml".equals(name) || "resources.arsc".equals(name)) return true;
        if (name.matches("classes(\\d*)\\.dex")) return true;
        return name.startsWith("lib/") && name.endsWith(".so");
    }

    private static String hashEntry(ZipFile zip, ZipEntry entry) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[32 * 1024];
        try (InputStream in = zip.getInputStream(entry)) {
            int n;
            while ((n = in.read(buffer)) != -1) digest.update(buffer, 0, n);
        }
        return hex(digest.digest());
    }

    private long versionCode() throws Exception {
        PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) return info.getLongVersionCode();
        return info.versionCode;
    }

    private String mac(long version, String map) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(getOrCreateKey());
        String payload = version + "|component-integrity-v1|" + map;
        return Base64.encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
    }

    private SecretKey getOrCreateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(HMAC_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(HMAC_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setKeySize(256).build());
        return generator.generateKey();
    }

    private static String sha256(byte[] data) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(data));
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

    private static String shortHash(String value) {
        if (value == null || value.isEmpty()) return "n/a";
        return value.length() <= 12 ? value : value.substring(0, 12);
    }

    private static final class ComponentMap {
        final String canonical;
        final int componentCount;
        ComponentMap(String canonical, int componentCount) {
            this.canonical = canonical;
            this.componentCount = componentCount;
        }
    }
}
