package com.rstlab.trailnote.securityplant;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Locale;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/** Tamper-evident local security event ledger backed by an Android Keystore HMAC key. */
final class TamperLedger {
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "trailnote.securityplant.ledger.hmac.v1";
    private static final String PREF = "trailnote_securityplant_ledger_v1";
    private static final String KEY_EVENTS = "events";
    private static final String KEY_ANCHOR = "anchor";
    private static final String KEY_LAST = "last";
    private static final int MAX_EVENTS = 96;
    private static final int TRIM_TO = 64;

    private final SharedPreferences prefs;

    TamperLedger(Context context) {
        prefs = context.getSharedPreferences(PREF, Context.MODE_PRIVATE);
    }

    synchronized boolean verify() {
        try {
            JSONArray events = new JSONArray(prefs.getString(KEY_EVENTS, "[]"));
            String prev = prefs.getString(KEY_ANCHOR, "GENESIS");
            for (int i = 0; i < events.length(); i++) {
                JSONObject e = events.getJSONObject(i);
                String declaredPrev = e.optString("prev", "");
                if (!constantTimeEquals(prev, declaredPrev)) return false;
                String expected = mac(e.getLong("ts"), e.getString("event"), e.optString("detail"), e.optInt("risk"), prev);
                if (!constantTimeEquals(expected, e.optString("mac", ""))) return false;
                prev = expected;
            }
            String last = prefs.getString(KEY_LAST, events.length() == 0 ? prev : "");
            return constantTimeEquals(prev, last);
        } catch (Exception e) {
            return false;
        }
    }

    synchronized void append(String event, String detail, int risk) {
        try {
            JSONArray events = new JSONArray(prefs.getString(KEY_EVENTS, "[]"));
            String prev = prefs.getString(KEY_LAST, prefs.getString(KEY_ANCHOR, "GENESIS"));
            long ts = System.currentTimeMillis();
            String safeDetail = sanitize(detail);
            String value = mac(ts, event, safeDetail, risk, prev);
            JSONObject obj = new JSONObject();
            obj.put("ts", ts);
            obj.put("event", sanitize(event));
            obj.put("detail", safeDetail);
            obj.put("risk", Math.max(0, Math.min(100, risk)));
            obj.put("prev", prev);
            obj.put("mac", value);
            events.put(obj);

            String anchor = prefs.getString(KEY_ANCHOR, "GENESIS");
            if (events.length() > MAX_EVENTS) {
                while (events.length() > TRIM_TO) {
                    JSONObject removed = events.getJSONObject(0);
                    anchor = removed.getString("mac");
                    JSONArray next = new JSONArray();
                    for (int i = 1; i < events.length(); i++) next.put(events.get(i));
                    events = next;
                }
            }
            prefs.edit()
                    .putString(KEY_EVENTS, events.toString())
                    .putString(KEY_ANCHOR, anchor)
                    .putString(KEY_LAST, value)
                    .commit();
        } catch (Exception ignored) {
        }
    }

    synchronized String diagnosticSummary() {
        try {
            JSONArray events = new JSONArray(prefs.getString(KEY_EVENTS, "[]"));
            return "ledgerEvents=" + events.length() + ", integrity=" + (verify() ? "OK" : "FAILED");
        } catch (Exception e) {
            return "ledger unavailable";
        }
    }

    private String mac(long ts, String event, String detail, int risk, String prev) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(getOrCreateKey());
        String payload = ts + "|" + event + "|" + detail + "|" + risk + "|" + prev;
        return Base64.encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)), Base64.NO_WRAP);
    }

    private SecretKey getOrCreateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }

    private static String sanitize(String value) {
        if (value == null) return "";
        String out = value.replace('\n', ' ').replace('\r', ' ').replace('|', '/');
        return out.length() > 180 ? out.substring(0, 180) : out;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }
}
