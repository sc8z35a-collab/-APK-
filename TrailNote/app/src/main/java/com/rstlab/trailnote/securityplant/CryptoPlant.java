package com.rstlab.trailnote.securityplant;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Iterator;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Security Container Plant cryptographic root.
 *
 * v4 hierarchy:
 *   StrongBox/Android-Keystore hardware root (or PIN-unwrapped session root)
 *       -> random 256-bit Workspace KEK
 *           -> independent random 256-bit Domain DEKs
 *               -> logs / spots / plans / missions / assets / gear
 *
 * Legacy direct/M2/M3 payloads remain readable and are rewritten as H4 after a
 * successful authenticated read. Existing v2/v3 PIN metadata is upgraded in-place.
 */
final class CryptoPlant {
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String LEGACY_KEY_ALIAS = "trailnote.vault.aes.v1";
    private static final String HARDWARE_KEY_ALIAS = "trailnote.vault.aes.v2.hardware";
    private static final String PREF_SECURITY = "trailnote_security_v1";
    private static final String PREF_SECURE_DATA = "trailnote_secure_data_v1";
    private static final String KEY_ENTRIES = "entries_enc";
    private static final String KEY_PIN_SALT = "pin_salt";
    private static final String KEY_PIN_HASH = "pin_hash";
    private static final String KEY_WRAP_SALT = "wrap_salt";
    private static final String KEY_MASTER_WRAP = "master_wrap";
    private static final String KEY_PIN_VERSION = "pin_version";
    private static final String KEY_FAILED = "failed_attempts";
    private static final String KEY_LOCK_UNTIL = "lock_until";
    private static final String KEY_HW_MODE = "hardware_root_mode";
    private static final String KEY_WORKSPACE_KEK_WRAP = "workspace_kek_wrap_v1";
    private static final String DOMAIN_WRAP_PREFIX = "domain_dek_wrap_";
    private static final String MASTER_PREFIX = "M3.";
    private static final String HIERARCHY_PREFIX = "H4.";
    private static final int LEGACY_PIN_ITERATIONS = 160_000;
    private static final int LEGACY_WRAP_ITERATIONS = 220_000;
    private static final int PIN_ITERATIONS = 240_000;
    private static final int WRAP_ITERATIONS = 420_000;
    private static final int BACKUP_ITERATIONS = 420_000;
    private static final int GCM_TAG_BITS = 128;
    private static final int PIN_VERSION = 4;
    private static final String[] DOMAINS = {"logs", "spots", "plans", "missions", "assets", "gear"};

    private final SharedPreferences securityPrefs;
    private final SharedPreferences secureDataPrefs;
    private final SecureRandom random = new SecureRandom();
    private byte[] sessionMasterKey;

    CryptoPlant(Context context) {
        securityPrefs = context.getSharedPreferences(PREF_SECURITY, Context.MODE_PRIVATE);
        secureDataPrefs = context.getSharedPreferences(PREF_SECURE_DATA, Context.MODE_PRIVATE);
    }

    boolean hasPin() {
        return securityPrefs.contains(KEY_PIN_SALT)
                && securityPrefs.contains(KEY_PIN_HASH)
                && securityPrefs.contains(KEY_WRAP_SALT)
                && securityPrefs.contains(KEY_MASTER_WRAP);
    }

    void setPin(String pin) throws Exception {
        if (!isValidPin(pin)) throw new IllegalArgumentException("PINは6〜12桁で設定してください");
        boolean changing = hasPin();
        String existingPlain = null;
        byte[] existingWorkspaceKek = null;

        if (changing) {
            if (sessionMasterKey == null) throw new SecurityException("PIN変更前にVaultを解除してください");
        } else {
            String current = secureDataPrefs.getString(KEY_ENTRIES, null);
            if (current != null && current.startsWith(HIERARCHY_PREFIX)) {
                existingWorkspaceKek = getOrCreateWorkspaceKek(); // current no-PIN boundary
                existingPlain = decryptHierarchyEnvelope(current.substring(HIERARCHY_PREFIX.length()));
            } else if (current != null && !current.startsWith("M2.") && !current.startsWith(MASTER_PREFIX)) {
                existingPlain = decryptLocalDirect(current);
            }
            sessionMasterKey = randomBytes(32);
        }

        writePinMetadata(pin, PIN_ITERATIONS, WRAP_ITERATIONS, PIN_VERSION,
                "SecurityPlantMaster:pin:v4", "SecurityPlantMaster:hardware:v4", true);

        if (!changing) {
            if (existingWorkspaceKek != null) {
                try {
                    storeWorkspaceKek(existingWorkspaceKek, true);
                } finally {
                    Arrays.fill(existingWorkspaceKek, (byte) 0);
                }
            }
            // H4 metadata is root-bound, so re-encrypt after moving the Workspace KEK boundary.
            if (existingPlain != null) saveEntries(existingPlain);
        }
    }

    boolean verifyPin(String pin) throws Exception {
        if (!hasPin()) return true;
        if (isLockedOut()) return false;

        int version = securityPrefs.getInt(KEY_PIN_VERSION, 2);
        int pinIterations = version >= 4 ? PIN_ITERATIONS : (version >= 3 ? 220_000 : LEGACY_PIN_ITERATIONS);
        int wrapIterations = version >= 4 ? WRAP_ITERATIONS : (version >= 3 ? 360_000 : LEGACY_WRAP_ITERATIONS);
        String pinAad = version >= 4 ? "SecurityPlantMaster:pin:v4"
                : version >= 3 ? "SecurityPlantMaster:pin:v3" : "TrailNoteMasterWrap:pin:v2";
        String keystoreAad = version >= 4 ? "SecurityPlantMaster:hardware:v4"
                : version >= 3 ? "SecurityPlantMaster:keystore:v3" : "TrailNoteMasterWrap:keystore:v2";

        byte[] salt = unb64(securityPrefs.getString(KEY_PIN_SALT, ""));
        byte[] expected = unb64(securityPrefs.getString(KEY_PIN_HASH, ""));
        byte[] actual = pbkdf2(pin.toCharArray(), salt, pinIterations, expected.length);
        boolean ok = constantTimeEquals(expected, actual);
        Arrays.fill(actual, (byte) 0);
        if (!ok) {
            registerFailedAttempt();
            return false;
        }

        byte[] wrapSalt = unb64(securityPrefs.getString(KEY_WRAP_SALT, ""));
        byte[] pinWrapKey = pbkdf2(pin.toCharArray(), wrapSalt, wrapIterations, 32);
        try {
            byte[] keystoreWrappedBytes = decryptWithRawKey(
                    securityPrefs.getString(KEY_MASTER_WRAP, ""), pinWrapKey, pinAad);
            byte[] master = version >= 4
                    ? decryptWithCurrentKeystore(new String(keystoreWrappedBytes, StandardCharsets.UTF_8), keystoreAad)
                    : decryptWithLegacyKeystore(new String(keystoreWrappedBytes, StandardCharsets.UTF_8), keystoreAad);
            Arrays.fill(keystoreWrappedBytes, (byte) 0);
            if (master.length != 32) throw new SecurityException("Vault master key length mismatch");
            lockSession();
            sessionMasterKey = master;
            securityPrefs.edit().putInt(KEY_FAILED, 0).putLong(KEY_LOCK_UNTIL, 0L).apply();

            if (version < PIN_VERSION) {
                // Same in-memory root, newly wrapped by StrongBox/modern Keystore and v4 KDF metadata.
                writePinMetadata(pin, PIN_ITERATIONS, WRAP_ITERATIONS, PIN_VERSION,
                        "SecurityPlantMaster:pin:v4", "SecurityPlantMaster:hardware:v4", true);
            }
            migrateLegacyPayloadIfNeeded();
            return true;
        } catch (Exception e) {
            registerFailedAttempt();
            lockSession();
            return false;
        } finally {
            Arrays.fill(pinWrapKey, (byte) 0);
        }
    }

    private void writePinMetadata(String pin, int pinIterations, int wrapIterations, int version,
                                  String pinAad, String keystoreAad, boolean modernKeystore) throws Exception {
        if (sessionMasterKey == null) throw new SecurityException("Vault root key unavailable");
        byte[] verifySalt = randomBytes(16);
        byte[] verifyHash = pbkdf2(pin.toCharArray(), verifySalt, pinIterations, 32);
        byte[] wrapSalt = randomBytes(16);
        byte[] pinWrapKey = pbkdf2(pin.toCharArray(), wrapSalt, wrapIterations, 32);
        try {
            String keystoreWrappedMaster = modernKeystore
                    ? encryptWithCurrentKeystore(sessionMasterKey, keystoreAad)
                    : encryptWithLegacyKeystore(sessionMasterKey, keystoreAad);
            String pinWrappedMaster = encryptWithRawKey(
                    keystoreWrappedMaster.getBytes(StandardCharsets.UTF_8), pinWrapKey, pinAad);
            boolean committed = securityPrefs.edit()
                    .putString(KEY_PIN_SALT, b64(verifySalt))
                    .putString(KEY_PIN_HASH, b64(verifyHash))
                    .putString(KEY_WRAP_SALT, b64(wrapSalt))
                    .putString(KEY_MASTER_WRAP, pinWrappedMaster)
                    .putInt(KEY_PIN_VERSION, version)
                    .putInt(KEY_FAILED, 0)
                    .putLong(KEY_LOCK_UNTIL, 0L)
                    .commit();
            if (!committed) throw new IllegalStateException("セキュリティー設定を保存できませんでした");
        } finally {
            Arrays.fill(verifyHash, (byte) 0);
            Arrays.fill(pinWrapKey, (byte) 0);
        }
    }

    void lockSession() {
        if (sessionMasterKey != null) {
            Arrays.fill(sessionMasterKey, (byte) 0);
            sessionMasterKey = null;
        }
    }

    boolean isSessionUnlocked() { return !hasPin() || sessionMasterKey != null; }
    boolean isLockedOut() { return System.currentTimeMillis() < lockoutUntil(); }
    long lockoutUntil() { return securityPrefs.getLong(KEY_LOCK_UNTIL, 0L); }
    int failedAttempts() { return securityPrefs.getInt(KEY_FAILED, 0); }

    String loadEntries(SharedPreferences legacyPrefs, String legacyKey) throws Exception {
        String encrypted = secureDataPrefs.getString(KEY_ENTRIES, null);
        if (encrypted == null) {
            String legacy = legacyPrefs.getString(legacyKey, "[]");
            saveEntries(legacy);
            legacyPrefs.edit().remove(legacyKey).apply();
            return legacy;
        }

        if (encrypted.startsWith(HIERARCHY_PREFIX)) {
            if (hasPin()) requireUnlocked();
            return decryptHierarchyEnvelope(encrypted.substring(HIERARCHY_PREFIX.length()));
        }

        String plain;
        if (hasPin()) {
            requireUnlocked();
            if (encrypted.startsWith(MASTER_PREFIX)) {
                plain = new String(decryptWithMaster(encrypted.substring(MASTER_PREFIX.length()),
                        "SecurityPlantEntries:master:v3"), StandardCharsets.UTF_8);
            } else if (encrypted.startsWith("M2.")) {
                plain = new String(decryptWithMaster(encrypted.substring(3),
                        "TrailNoteEntries:master:v2"), StandardCharsets.UTF_8);
            } else {
                plain = decryptLocalDirect(encrypted);
            }
        } else {
            if (encrypted.startsWith("M2.") || encrypted.startsWith(MASTER_PREFIX)) {
                throw new SecurityException("PIN metadata is missing for a protected vault");
            }
            plain = decryptLocalDirect(encrypted);
        }
        saveEntries(plain); // authenticated migration to H4
        return plain;
    }

    void saveEntries(String json) throws Exception {
        if (hasPin()) requireUnlocked();
        String packed = HIERARCHY_PREFIX + encryptHierarchyEnvelope(json);
        if (!secureDataPrefs.edit().putString(KEY_ENTRIES, packed).commit()) {
            throw new IllegalStateException("暗号化データを書き込めませんでした");
        }
    }

    boolean hasEncryptedData() { return secureDataPrefs.contains(KEY_ENTRIES); }

    boolean hierarchyConfigured() {
        String value = secureDataPrefs.getString(KEY_ENTRIES, "");
        return value.startsWith(HIERARCHY_PREFIX)
                && securityPrefs.contains(KEY_WORKSPACE_KEK_WRAP);
    }

    String summary() {
        return "Security Plant H4 Root→Workspace-KEK→Domain-DEK AES-256-GCM / " + hardwareBackedSummary()
                + (hasPin() ? " / PIN-wrapped root" : " / device-bound root");
    }

    String hardwareBackedSummary() {
        try {
            SecretKey key = getOrCreateHardwareKey();
            boolean secure = false;
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), KEYSTORE);
                KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
                secure = info.isInsideSecureHardware();
            } catch (Exception ignored) {
            }
            String mode = securityPrefs.getString(KEY_HW_MODE, "ANDROID_KEYSTORE");
            return mode + (secure ? "/HW" : "/KEYSTORE");
        } catch (Exception e) {
            return "KEYSTORE_UNAVAILABLE";
        }
    }

    String encryptBackup(String json, String passphrase) throws Exception {
        if (passphrase == null || passphrase.length() < 10) {
            throw new IllegalArgumentException("バックアップ用パスフレーズは10文字以上にしてください");
        }
        byte[] salt = randomBytes(16);
        byte[] iv = randomBytes(12);
        byte[] keyBytes = pbkdf2(passphrase.toCharArray(), salt, BACKUP_ITERATIONS, 32);
        try {
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD("SecurityContainerPlantBackup:v4".getBytes(StandardCharsets.UTF_8));
            byte[] ct = cipher.doFinal(json.getBytes(StandardCharsets.UTF_8));
            JSONObject envelope = new JSONObject();
            envelope.put("format", "TrailNoteSecurityPlant");
            envelope.put("version", 4);
            envelope.put("kdf", "PBKDF2WithHmacSHA256");
            envelope.put("iterations", BACKUP_ITERATIONS);
            envelope.put("cipher", "AES-256-GCM");
            envelope.put("salt", b64(salt));
            envelope.put("iv", b64(iv));
            envelope.put("ciphertext", b64(ct));
            return envelope.toString();
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    String decryptBackup(String envelopeText, String passphrase) throws Exception {
        JSONObject envelope = new JSONObject(envelopeText);
        String format = envelope.optString("format");
        if ("TrailNoteVault".equals(format)) return decryptBackupEnvelope(envelope, passphrase,
                envelope.optInt("iterations", LEGACY_WRAP_ITERATIONS), "TrailNoteBackup:v2");
        if (!"TrailNoteSecurityPlant".equals(format)) {
            throw new IllegalArgumentException("TrailNote Security Plantバックアップではありません");
        }
        int iterations = envelope.optInt("iterations", BACKUP_ITERATIONS);
        if (iterations < 100_000 || iterations > 1_000_000) throw new IllegalArgumentException("KDF設定が不正です");
        int version = envelope.optInt("version", 3);
        return decryptBackupEnvelope(envelope, passphrase, iterations,
                version >= 4 ? "SecurityContainerPlantBackup:v4" : "SecurityContainerPlantBackup:v3");
    }

    private String decryptBackupEnvelope(JSONObject envelope, String passphrase, int iterations, String aad) throws Exception {
        if (iterations < 100_000 || iterations > 1_000_000) throw new IllegalArgumentException("KDF設定が不正です");
        byte[] salt = unb64(envelope.getString("salt"));
        byte[] iv = unb64(envelope.getString("iv"));
        byte[] ct = unb64(envelope.getString("ciphertext"));
        byte[] keyBytes = pbkdf2(passphrase.toCharArray(), salt, iterations, 32);
        try {
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    private String encryptHierarchyEnvelope(String workspaceJson) throws Exception {
        JSONObject root;
        String trimmed = workspaceJson == null ? "" : workspaceJson.trim();
        if (trimmed.startsWith("[")) {
            root = new JSONObject();
            root.put("schema", 3);
            root.put("logs", new JSONArray(trimmed));
            for (String domain : DOMAINS) if (!root.has(domain)) root.put(domain, new JSONArray());
        } else {
            root = new JSONObject(trimmed);
        }

        JSONObject meta = new JSONObject();
        Iterator<String> keys = root.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            if (!isDomain(key)) meta.put(key, root.get(key));
        }

        JSONObject envelope = new JSONObject();
        envelope.put("format", "TrailNoteHierarchy");
        envelope.put("version", 1);
        envelope.put("meta", encryptRoot(meta.toString().getBytes(StandardCharsets.UTF_8),
                "SecurityPlantHierarchyMeta:v1"));
        JSONObject domains = new JSONObject();
        for (String domain : DOMAINS) {
            JSONArray array = root.optJSONArray(domain);
            if (array == null) array = new JSONArray();
            byte[] dek = getOrCreateDomainKey(domain);
            try {
                domains.put(domain, encryptWithRawKey(array.toString().getBytes(StandardCharsets.UTF_8), dek,
                        "SecurityPlantDomain:" + domain + ":v1"));
            } finally {
                Arrays.fill(dek, (byte) 0);
            }
        }
        envelope.put("domains", domains);
        return b64(envelope.toString().getBytes(StandardCharsets.UTF_8));
    }

    private String decryptHierarchyEnvelope(String encoded) throws Exception {
        JSONObject envelope = new JSONObject(new String(unb64(encoded), StandardCharsets.UTF_8));
        if (!"TrailNoteHierarchy".equals(envelope.optString("format")) || envelope.optInt("version") != 1) {
            throw new SecurityException("H4 hierarchy envelope rejected");
        }
        byte[] metaBytes = decryptRoot(envelope.getString("meta"), "SecurityPlantHierarchyMeta:v1");
        JSONObject root;
        try {
            root = new JSONObject(new String(metaBytes, StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(metaBytes, (byte) 0);
        }
        JSONObject domains = envelope.getJSONObject("domains");
        for (String domain : DOMAINS) {
            if (!domains.has(domain)) throw new SecurityException("H4 domain missing: " + domain);
            byte[] dek = getOrCreateDomainKey(domain);
            byte[] plain = null;
            try {
                plain = decryptWithRawKey(domains.getString(domain), dek,
                        "SecurityPlantDomain:" + domain + ":v1");
                root.put(domain, new JSONArray(new String(plain, StandardCharsets.UTF_8)));
            } finally {
                Arrays.fill(dek, (byte) 0);
                if (plain != null) Arrays.fill(plain, (byte) 0);
            }
        }
        return root.toString();
    }

    private byte[] getOrCreateWorkspaceKek() throws Exception {
        String stored = securityPrefs.getString(KEY_WORKSPACE_KEK_WRAP, null);
        if (stored != null) {
            return hasPin()
                    ? decryptWithMaster(stored, "SecurityPlantWorkspaceKEK:root:v1")
                    : decryptWithCurrentKeystore(stored, "SecurityPlantWorkspaceKEK:device:v1");
        }
        byte[] kek = randomBytes(32);
        storeWorkspaceKek(kek, hasPin());
        return kek;
    }

    private void storeWorkspaceKek(byte[] kek, boolean pinMode) throws Exception {
        String wrapped = pinMode
                ? encryptWithMaster(kek, "SecurityPlantWorkspaceKEK:root:v1")
                : encryptWithCurrentKeystore(kek, "SecurityPlantWorkspaceKEK:device:v1");
        if (!securityPrefs.edit().putString(KEY_WORKSPACE_KEK_WRAP, wrapped).commit()) {
            throw new IllegalStateException("Workspace KEK wrap commit failed");
        }
    }

    private byte[] getOrCreateDomainKey(String domain) throws Exception {
        byte[] workspaceKek = getOrCreateWorkspaceKek();
        try {
            String stored = securityPrefs.getString(DOMAIN_WRAP_PREFIX + domain, null);
            if (stored != null) {
                return decryptWithRawKey(stored, workspaceKek,
                        "SecurityPlantDomainDEK:" + domain + ":workspace:v1");
            }
            byte[] dek = randomBytes(32);
            String wrapped = encryptWithRawKey(dek, workspaceKek,
                    "SecurityPlantDomainDEK:" + domain + ":workspace:v1");
            if (!securityPrefs.edit().putString(DOMAIN_WRAP_PREFIX + domain, wrapped).commit()) {
                Arrays.fill(dek, (byte) 0);
                throw new IllegalStateException("Domain key wrap commit failed: " + domain);
            }
            return dek;
        } finally {
            Arrays.fill(workspaceKek, (byte) 0);
        }
    }

    private void migrateLegacyPayloadIfNeeded() throws Exception {
        String encrypted = secureDataPrefs.getString(KEY_ENTRIES, null);
        if (encrypted == null || encrypted.startsWith(HIERARCHY_PREFIX)) return;
        String plain;
        if (encrypted.startsWith(MASTER_PREFIX)) {
            plain = new String(decryptWithMaster(encrypted.substring(MASTER_PREFIX.length()),
                    "SecurityPlantEntries:master:v3"), StandardCharsets.UTF_8);
        } else if (encrypted.startsWith("M2.")) {
            plain = new String(decryptWithMaster(encrypted.substring(3),
                    "TrailNoteEntries:master:v2"), StandardCharsets.UTF_8);
        } else {
            plain = decryptLocalDirect(encrypted);
        }
        saveEntries(plain);
    }

    private void registerFailedAttempt() {
        int failed = failedAttempts() + 1;
        long until = 0L;
        if (failed >= 5) {
            int stage = Math.min(5, failed - 5);
            long seconds = 30L * (1L << stage);
            until = System.currentTimeMillis() + Math.min(seconds, 900L) * 1000L;
        }
        securityPrefs.edit().putInt(KEY_FAILED, failed).putLong(KEY_LOCK_UNTIL, until).apply();
    }

    private void requireUnlocked() {
        if (sessionMasterKey == null) throw new SecurityException("Security Container Plant is locked");
    }

    private String encryptWithMaster(byte[] plaintext, String aad) throws Exception {
        requireUnlocked();
        return encryptWithRawKey(plaintext, sessionMasterKey, aad);
    }

    private byte[] decryptWithMaster(String packed, String aad) throws Exception {
        requireUnlocked();
        return decryptWithRawKey(packed, sessionMasterKey, aad);
    }

    private String encryptRoot(byte[] plaintext, String aad) throws Exception {
        return hasPin() ? encryptWithMaster(plaintext, aad)
                : encryptWithCurrentKeystore(plaintext, aad);
    }

    private byte[] decryptRoot(String packed, String aad) throws Exception {
        return hasPin() ? decryptWithMaster(packed, aad)
                : decryptWithCurrentKeystore(packed, aad);
    }

    private String encryptLocalDirect(String plaintext) throws Exception {
        return "K2." + encryptWithCurrentKeystore(plaintext.getBytes(StandardCharsets.UTF_8),
                "SecurityPlantLocal:direct:v4");
    }

    private String decryptLocalDirect(String packed) throws Exception {
        if (packed.startsWith("K2.")) {
            return new String(decryptWithCurrentKeystore(packed.substring(3),
                    "SecurityPlantLocal:direct:v4"), StandardCharsets.UTF_8);
        }
        try {
            return new String(decryptWithLegacyKeystore(packed,
                    "SecurityPlantLocal:direct:v3"), StandardCharsets.UTF_8);
        } catch (Exception first) {
            return new String(decryptWithLegacyKeystore(packed,
                    "TrailNoteLocal:direct:v1"), StandardCharsets.UTF_8);
        }
    }

    private String encryptWithCurrentKeystore(byte[] plaintext, String aad) throws Exception {
        return encryptWithKeystore(getOrCreateHardwareKey(), plaintext, aad);
    }

    private byte[] decryptWithCurrentKeystore(String packed, String aad) throws Exception {
        return decryptWithKeystore(getOrCreateHardwareKey(), packed, aad);
    }

    private String encryptWithLegacyKeystore(byte[] plaintext, String aad) throws Exception {
        return encryptWithKeystore(getOrCreateLegacyKey(), plaintext, aad);
    }

    private byte[] decryptWithLegacyKeystore(String packed, String aad) throws Exception {
        return decryptWithKeystore(getOrCreateLegacyKey(), packed, aad);
    }

    private String encryptWithKeystore(SecretKey key, byte[] plaintext, String aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // Android Keystore owns IV generation for randomized GCM encryption.
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        byte[] ct = cipher.doFinal(plaintext);
        byte[] iv = cipher.getIV();
        if (iv == null || iv.length < 12) throw new SecurityException("Keystore did not supply a valid GCM IV");
        return b64(iv) + "." + b64(ct);
    }

    private byte[] decryptWithKeystore(SecretKey key, String packed, String aad) throws Exception {
        String[] parts = packed.split("\\.", 2);
        if (parts.length != 2) throw new IllegalArgumentException("暗号化データ形式が不正です");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, unb64(parts[0])));
        cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(unb64(parts[1]));
    }

    private String encryptWithRawKey(byte[] plaintext, byte[] keyBytes, String aad) throws Exception {
        byte[] iv = randomBytes(12);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        return b64(iv) + "." + b64(cipher.doFinal(plaintext));
    }

    private byte[] decryptWithRawKey(String packed, byte[] keyBytes, String aad) throws Exception {
        String[] parts = packed.split("\\.", 2);
        if (parts.length != 2) throw new IllegalArgumentException("暗号化データ形式が不正です");
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, unb64(parts[0])));
        cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(unb64(parts[1]));
    }

    private SecretKey getOrCreateHardwareKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        KeyStore.Entry existing = ks.getEntry(HARDWARE_KEY_ALIAS, null);
        if (existing instanceof KeyStore.SecretKeyEntry) return ((KeyStore.SecretKeyEntry) existing).getSecretKey();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                SecretKey key = generateHardwareKey(true);
                securityPrefs.edit().putString(KEY_HW_MODE, "STRONGBOX").commit();
                return key;
            } catch (Exception strongBoxUnavailableOrUnsupported) {
                // Explicit fallback to the normal Android Keystore, normally TEE-backed when available.
            }
        }
        SecretKey key = generateHardwareKey(false);
        securityPrefs.edit().putString(KEY_HW_MODE, "TEE_FALLBACK").commit();
        return key;
    }

    private SecretKey generateHardwareKey(boolean strongBox) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(HARDWARE_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true);
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(true);
        generator.init(builder.build());
        return generator.generateKey();
    }

    private SecretKey getOrCreateLegacyKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
        keyStore.load(null);
        KeyStore.Entry entry = keyStore.getEntry(LEGACY_KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(LEGACY_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build());
        return generator.generateKey();
    }

    private static byte[] pbkdf2(char[] chars, byte[] salt, int iterations, int bytes) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, bytes * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
            Arrays.fill(chars, '\0');
        }
    }

    private byte[] randomBytes(int size) {
        byte[] out = new byte[size];
        random.nextBytes(out);
        return out;
    }

    private static boolean isDomain(String key) {
        for (String domain : DOMAINS) if (domain.equals(key)) return true;
        return false;
    }

    private static boolean isValidPin(String pin) { return pin != null && pin.matches("\\d{6,12}"); }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static String b64(byte[] data) { return Base64.encodeToString(data, Base64.NO_WRAP); }
    private static byte[] unb64(String text) { return Base64.decode(text, Base64.NO_WRAP); }
}
