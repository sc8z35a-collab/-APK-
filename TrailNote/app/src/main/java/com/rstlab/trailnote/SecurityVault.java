package com.rstlab.trailnote;

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
 * Independent local security layer for TrailNote.
 *
 * - AES-256-GCM key lives in Android Keystore.
 * - App PIN is stored only as PBKDF2-HMAC-SHA256(salt, pin).
 * - Failed PIN attempts trigger an exponential temporary lockout.
 * - Backup files are independently encrypted with a user passphrase.
 */
public final class SecurityVault {
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "trailnote.vault.aes.v1";
    private static final String PREF_SECURITY = "trailnote_security_v1";
    private static final String PREF_SECURE_DATA = "trailnote_secure_data_v1";
    private static final String KEY_ENTRIES = "entries_enc";
    private static final String KEY_PIN_SALT = "pin_salt";
    private static final String KEY_PIN_HASH = "pin_hash";
    private static final String KEY_FAILED = "failed_attempts";
    private static final String KEY_LOCK_UNTIL = "lock_until";
    private static final int PIN_ITERATIONS = 140_000;
    private static final int BACKUP_ITERATIONS = 180_000;
    private static final int GCM_TAG_BITS = 128;

    private final SharedPreferences securityPrefs;
    private final SharedPreferences secureDataPrefs;
    private final SecureRandom random = new SecureRandom();

    public SecurityVault(Context context) {
        securityPrefs = context.getSharedPreferences(PREF_SECURITY, Context.MODE_PRIVATE);
        secureDataPrefs = context.getSharedPreferences(PREF_SECURE_DATA, Context.MODE_PRIVATE);
    }

    public boolean hasPin() {
        return securityPrefs.contains(KEY_PIN_SALT) && securityPrefs.contains(KEY_PIN_HASH);
    }

    public void setPin(String pin) throws Exception {
        if (!isValidPin(pin)) throw new IllegalArgumentException("PINは6〜12桁で設定してください");
        byte[] salt = randomBytes(16);
        byte[] hash = pbkdf2(pin.toCharArray(), salt, PIN_ITERATIONS, 32);
        securityPrefs.edit()
                .putString(KEY_PIN_SALT, b64(salt))
                .putString(KEY_PIN_HASH, b64(hash))
                .putInt(KEY_FAILED, 0)
                .putLong(KEY_LOCK_UNTIL, 0L)
                .apply();
        Arrays.fill(hash, (byte) 0);
    }

    public boolean verifyPin(String pin) throws Exception {
        if (!hasPin()) return true;
        if (isLockedOut()) return false;
        byte[] salt = unb64(securityPrefs.getString(KEY_PIN_SALT, ""));
        byte[] expected = unb64(securityPrefs.getString(KEY_PIN_HASH, ""));
        byte[] actual = pbkdf2(pin.toCharArray(), salt, PIN_ITERATIONS, expected.length);
        boolean ok = constantTimeEquals(expected, actual);
        Arrays.fill(actual, (byte) 0);
        if (ok) {
            securityPrefs.edit().putInt(KEY_FAILED, 0).putLong(KEY_LOCK_UNTIL, 0L).apply();
            return true;
        }
        registerFailedAttempt();
        return false;
    }

    public boolean isLockedOut() {
        return System.currentTimeMillis() < lockoutUntil();
    }

    public long lockoutUntil() {
        return securityPrefs.getLong(KEY_LOCK_UNTIL, 0L);
    }

    public int failedAttempts() {
        return securityPrefs.getInt(KEY_FAILED, 0);
    }

    private void registerFailedAttempt() {
        int failed = failedAttempts() + 1;
        long until = 0L;
        if (failed >= 5) {
            int stage = Math.min(4, failed - 5);
            long seconds = 30L * (1L << stage); // 30s, 60s, 120s, 240s, 480s max progression
            until = System.currentTimeMillis() + Math.min(seconds, 480L) * 1000L;
        }
        securityPrefs.edit().putInt(KEY_FAILED, failed).putLong(KEY_LOCK_UNTIL, until).apply();
    }

    public String loadEntries(SharedPreferences legacyPrefs, String legacyKey) {
        try {
            String encrypted = secureDataPrefs.getString(KEY_ENTRIES, null);
            if (encrypted != null) return decryptLocal(encrypted);

            // One-time migration from v1.x plaintext SharedPreferences.
            String legacy = legacyPrefs.getString(legacyKey, "[]");
            saveEntries(legacy);
            legacyPrefs.edit().remove(legacyKey).apply();
            return legacy;
        } catch (Exception e) {
            return "[]";
        }
    }

    public void saveEntries(String json) throws Exception {
        secureDataPrefs.edit().putString(KEY_ENTRIES, encryptLocal(json)).apply();
    }

    public boolean hasEncryptedData() {
        return secureDataPrefs.contains(KEY_ENTRIES);
    }

    public String securitySummary() {
        return "AES-256-GCM / Android Keystore / PBKDF2-SHA256 / GCM tag 128-bit";
    }

    public String encryptBackup(String json, String passphrase) throws Exception {
        if (passphrase == null || passphrase.length() < 8) {
            throw new IllegalArgumentException("バックアップ用パスフレーズは8文字以上にしてください");
        }
        byte[] salt = randomBytes(16);
        byte[] iv = randomBytes(12);
        byte[] keyBytes = pbkdf2(passphrase.toCharArray(), salt, BACKUP_ITERATIONS, 32);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD("TrailNoteBackup:v2".getBytes(StandardCharsets.UTF_8));
        byte[] ct = cipher.doFinal(json.getBytes(StandardCharsets.UTF_8));
        Arrays.fill(keyBytes, (byte) 0);

        JSONObject envelope = new JSONObject();
        envelope.put("format", "TrailNoteVault");
        envelope.put("version", 2);
        envelope.put("kdf", "PBKDF2WithHmacSHA256");
        envelope.put("iterations", BACKUP_ITERATIONS);
        envelope.put("cipher", "AES-256-GCM");
        envelope.put("salt", b64(salt));
        envelope.put("iv", b64(iv));
        envelope.put("ciphertext", b64(ct));
        return envelope.toString();
    }

    public String decryptBackup(String envelopeText, String passphrase) throws Exception {
        JSONObject envelope = new JSONObject(envelopeText);
        if (!"TrailNoteVault".equals(envelope.optString("format"))) {
            throw new IllegalArgumentException("TrailNote暗号化バックアップではありません");
        }
        int iterations = envelope.optInt("iterations", BACKUP_ITERATIONS);
        if (iterations < 100_000 || iterations > 1_000_000) {
            throw new IllegalArgumentException("KDF設定が不正です");
        }
        byte[] salt = unb64(envelope.getString("salt"));
        byte[] iv = unb64(envelope.getString("iv"));
        byte[] ct = unb64(envelope.getString("ciphertext"));
        byte[] keyBytes = pbkdf2(passphrase.toCharArray(), salt, iterations, 32);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD("TrailNoteBackup:v2".getBytes(StandardCharsets.UTF_8));
        byte[] plain = cipher.doFinal(ct);
        Arrays.fill(keyBytes, (byte) 0);
        return new String(plain, StandardCharsets.UTF_8);
    }

    private String encryptLocal(String plaintext) throws Exception {
        SecretKey key = getOrCreateKey();
        byte[] iv = randomBytes(12);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD("TrailNoteLocal:v1".getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return b64(iv) + "." + b64(ciphertext);
    }

    private String decryptLocal(String packed) throws Exception {
        String[] parts = packed.split("\\.", 2);
        if (parts.length != 2) throw new IllegalArgumentException("暗号化データ形式が不正です");
        SecretKey key = getOrCreateKey();
        byte[] iv = unb64(parts[0]);
        byte[] ciphertext = unb64(parts[1]);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD("TrailNoteLocal:v1".getBytes(StandardCharsets.UTF_8));
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    private SecretKey getOrCreateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
        keyStore.load(null);
        KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
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
