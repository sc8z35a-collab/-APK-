package com.rstlab.trailnote.securityplant;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cryptographic core for Security Container Plant.
 *
 * PIN enabled mode is dual-key:
 * 1) random 256-bit master key encrypts protected app data with AES-GCM;
 * 2) an Android Keystore AES key wraps the master key;
 * 3) a separately salted PIN-derived AES key wraps the Keystore-wrapped blob.
 *
 * v1.3 PIN metadata (160k/220k PBKDF2 and M2 payloads) is accepted, then
 * upgraded in-place to the stronger v3 KDF metadata and M3 payload format.
 */
final class CryptoPlant {
    private static final String KEYSTORE = "AndroidKeyStore";
    // Preserve the existing device-bound key so v1.x ciphertext remains decryptable.
    private static final String KEY_ALIAS = "trailnote.vault.aes.v1";
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
    private static final String MASTER_PREFIX = "M3.";
    private static final int LEGACY_PIN_ITERATIONS = 160_000;
    private static final int LEGACY_WRAP_ITERATIONS = 220_000;
    private static final int PIN_ITERATIONS = 220_000;
    private static final int WRAP_ITERATIONS = 360_000;
    private static final int BACKUP_ITERATIONS = 360_000;
    private static final int GCM_TAG_BITS = 128;

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
        String existingDirectCipher = null;
        if (changing) {
            if (sessionMasterKey == null) throw new SecurityException("PIN変更前にVaultを解除してください");
        } else {
            sessionMasterKey = randomBytes(32);
            String current = secureDataPrefs.getString(KEY_ENTRIES, null);
            if (current != null && !current.startsWith("M2.") && !current.startsWith(MASTER_PREFIX)) {
                existingDirectCipher = current;
            }
        }

        writePinMetadata(pin, PIN_ITERATIONS, WRAP_ITERATIONS, 3,
                "SecurityPlantMaster:pin:v3", "SecurityPlantMaster:keystore:v3");

        if (!changing && existingDirectCipher != null) {
            String plain = decryptLocalDirect(existingDirectCipher);
            saveEntries(plain);
        }
    }

    boolean verifyPin(String pin) throws Exception {
        if (!hasPin()) return true;
        if (isLockedOut()) return false;

        int version = securityPrefs.getInt(KEY_PIN_VERSION, 2);
        int pinIterations = version >= 3 ? PIN_ITERATIONS : LEGACY_PIN_ITERATIONS;
        int wrapIterations = version >= 3 ? WRAP_ITERATIONS : LEGACY_WRAP_ITERATIONS;
        String pinAad = version >= 3 ? "SecurityPlantMaster:pin:v3" : "TrailNoteMasterWrap:pin:v2";
        String keystoreAad = version >= 3 ? "SecurityPlantMaster:keystore:v3" : "TrailNoteMasterWrap:keystore:v2";

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
            byte[] master = decryptWithKeystore(
                    new String(keystoreWrappedBytes, StandardCharsets.UTF_8), keystoreAad);
            Arrays.fill(keystoreWrappedBytes, (byte) 0);
            if (master.length != 32) throw new SecurityException("Vault master key length mismatch");
            lockSession();
            sessionMasterKey = master;
            securityPrefs.edit().putInt(KEY_FAILED, 0).putLong(KEY_LOCK_UNTIL, 0L).apply();

            if (version < 3) {
                writePinMetadata(pin, PIN_ITERATIONS, WRAP_ITERATIONS, 3,
                        "SecurityPlantMaster:pin:v3", "SecurityPlantMaster:keystore:v3");
            }
            migrateLegacyMasterPrefixIfNeeded();
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
                                  String pinAad, String keystoreAad) throws Exception {
        if (sessionMasterKey == null) throw new SecurityException("Vault master key unavailable");
        byte[] verifySalt = randomBytes(16);
        byte[] verifyHash = pbkdf2(pin.toCharArray(), verifySalt, pinIterations, 32);
        byte[] wrapSalt = randomBytes(16);
        byte[] pinWrapKey = pbkdf2(pin.toCharArray(), wrapSalt, wrapIterations, 32);
        try {
            String keystoreWrappedMaster = encryptWithKeystore(sessionMasterKey, keystoreAad);
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

    boolean isSessionUnlocked() {
        return !hasPin() || sessionMasterKey != null;
    }

    boolean isLockedOut() {
        return System.currentTimeMillis() < lockoutUntil();
    }

    long lockoutUntil() {
        return securityPrefs.getLong(KEY_LOCK_UNTIL, 0L);
    }

    int failedAttempts() {
        return securityPrefs.getInt(KEY_FAILED, 0);
    }

    String loadEntries(SharedPreferences legacyPrefs, String legacyKey) throws Exception {
        String encrypted = secureDataPrefs.getString(KEY_ENTRIES, null);
        if (encrypted == null) {
            String legacy = legacyPrefs.getString(legacyKey, "[]");
            saveEntries(legacy);
            legacyPrefs.edit().remove(legacyKey).apply();
            return legacy;
        }
        if (hasPin()) {
            requireUnlocked();
            if (encrypted.startsWith(MASTER_PREFIX)) {
                return decryptWithMaster(encrypted.substring(MASTER_PREFIX.length()), "SecurityPlantEntries:master:v3");
            }
            if (encrypted.startsWith("M2.")) {
                String plain = decryptWithMaster(encrypted.substring(3), "TrailNoteEntries:master:v2");
                saveEntries(plain);
                return plain;
            }
            String plain = decryptLocalDirect(encrypted);
            saveEntries(plain);
            return plain;
        }
        if (encrypted.startsWith("M2.") || encrypted.startsWith(MASTER_PREFIX)) {
            throw new SecurityException("PIN metadata is missing for a protected vault");
        }
        return decryptLocalDirect(encrypted);
    }

    void saveEntries(String json) throws Exception {
        String packed;
        if (hasPin()) {
            requireUnlocked();
            packed = MASTER_PREFIX + encryptWithMaster(json, "SecurityPlantEntries:master:v3");
        } else {
            packed = encryptLocalDirect(json);
        }
        if (!secureDataPrefs.edit().putString(KEY_ENTRIES, packed).commit()) {
            throw new IllegalStateException("暗号化データを書き込めませんでした");
        }
    }

    boolean hasEncryptedData() {
        return secureDataPrefs.contains(KEY_ENTRIES);
    }

    String summary() {
        return hasPin()
                ? "Security Plant dual-key AES-256-GCM / strengthened PIN KDF + Android Keystore"
                : "Security Plant AES-256-GCM / Android Keystore / authenticated encryption";
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
            cipher.updateAAD("SecurityContainerPlantBackup:v3".getBytes(StandardCharsets.UTF_8));
            byte[] ct = cipher.doFinal(json.getBytes(StandardCharsets.UTF_8));
            JSONObject envelope = new JSONObject();
            envelope.put("format", "TrailNoteSecurityPlant");
            envelope.put("version", 3);
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
        if ("TrailNoteVault".equals(format)) return decryptLegacyBackup(envelope, passphrase);
        if (!"TrailNoteSecurityPlant".equals(format)) {
            throw new IllegalArgumentException("TrailNote Security Plantバックアップではありません");
        }
        int iterations = envelope.optInt("iterations", BACKUP_ITERATIONS);
        if (iterations < 100_000 || iterations > 1_000_000) throw new IllegalArgumentException("KDF設定が不正です");
        return decryptBackupEnvelope(envelope, passphrase, iterations, "SecurityContainerPlantBackup:v3");
    }

    private String decryptLegacyBackup(JSONObject envelope, String passphrase) throws Exception {
        int iterations = envelope.optInt("iterations", LEGACY_WRAP_ITERATIONS);
        if (iterations < 100_000 || iterations > 1_000_000) throw new IllegalArgumentException("KDF設定が不正です");
        return decryptBackupEnvelope(envelope, passphrase, iterations, "TrailNoteBackup:v2");
    }

    private String decryptBackupEnvelope(JSONObject envelope, String passphrase, int iterations, String aad) throws Exception {
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

    private void migrateLegacyMasterPrefixIfNeeded() throws Exception {
        String encrypted = secureDataPrefs.getString(KEY_ENTRIES, null);
        if (encrypted != null && encrypted.startsWith("M2.")) {
            String plain = decryptWithMaster(encrypted.substring(3), "TrailNoteEntries:master:v2");
            saveEntries(plain);
        }
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

    private String encryptWithMaster(String plaintext, String aad) throws Exception {
        requireUnlocked();
        return encryptWithRawKey(plaintext.getBytes(StandardCharsets.UTF_8), sessionMasterKey, aad);
    }

    private String decryptWithMaster(String packed, String aad) throws Exception {
        requireUnlocked();
        return new String(decryptWithRawKey(packed, sessionMasterKey, aad), StandardCharsets.UTF_8);
    }

    private String encryptLocalDirect(String plaintext) throws Exception {
        return encryptWithKeystore(plaintext.getBytes(StandardCharsets.UTF_8), "SecurityPlantLocal:direct:v3");
    }

    private String decryptLocalDirect(String packed) throws Exception {
        try {
            return new String(decryptWithKeystore(packed, "SecurityPlantLocal:direct:v3"), StandardCharsets.UTF_8);
        } catch (Exception first) {
            return new String(decryptWithKeystore(packed, "TrailNoteLocal:direct:v1"), StandardCharsets.UTF_8);
        }
    }

    private String encryptWithKeystore(byte[] plaintext, String aad) throws Exception {
        SecretKey key = getOrCreateKey();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // Android Keystore keys created with randomized encryption required MUST
        // generate their own IV. Supplying a caller-generated GCM IV here causes
        // KeyStoreException: "Caller-provided IV not permitted" on real devices.
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] iv = cipher.getIV();
        if (iv == null || iv.length < 12) throw new SecurityException("Android Keystore did not provide a valid GCM IV");
        return b64(iv) + "." + b64(ciphertext);
    }

    private byte[] decryptWithKeystore(String packed, String aad) throws Exception {
        String[] parts = packed.split("\\.", 2);
        if (parts.length != 2) throw new IllegalArgumentException("暗号化データ形式が不正です");
        SecretKey key = getOrCreateKey();
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

    private SecretKey getOrCreateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
        keyStore.load(null);
        KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
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

    private static boolean isValidPin(String pin) {
        return pin != null && pin.matches("\\d{6,12}");
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static String b64(byte[] data) {
        return Base64.encodeToString(data, Base64.NO_WRAP);
    }

    private static byte[] unb64(String text) {
        return Base64.decode(text, Base64.NO_WRAP);
    }
}
