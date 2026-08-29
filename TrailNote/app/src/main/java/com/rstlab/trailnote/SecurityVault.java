package com.rstlab.trailnote;

import android.content.Context;
import android.content.SharedPreferences;

import com.rstlab.trailnote.securityplant.SecurityContainerPlant;

/**
 * Compatibility adapter.
 *
 * The security implementation no longer lives here. Every sensitive operation is
 * routed through the independent securityplant/ layer so existing UI code cannot
 * bypass the Security Container Plant policy checkpoints.
 */
public final class SecurityVault {
    private final SecurityContainerPlant plant;

    public SecurityVault(Context context) {
        plant = new SecurityContainerPlant(context);
    }

    public boolean hasPin() { return plant.hasPin(); }
    public void setPin(String pin) throws Exception { plant.setPin(pin); }
    public boolean verifyPin(String pin) throws Exception { return plant.verifyPin(pin); }
    public void lockSession() { plant.lockSession(); }
    public boolean isSessionUnlocked() { return plant.isSessionUnlocked(); }
    public boolean isLockedOut() { return plant.isLockedOut(); }
    public long lockoutUntil() { return plant.lockoutUntil(); }
    public int failedAttempts() { return plant.failedAttempts(); }

    public String loadEntries(SharedPreferences legacyPrefs, String legacyKey) throws Exception {
        return plant.loadEntries(legacyPrefs, legacyKey);
    }

    public void saveEntries(String json) throws Exception { plant.saveEntries(json); }
    public boolean hasEncryptedData() { return plant.hasEncryptedData(); }
    public String securitySummary() { return plant.securitySummary(); }
    public String encryptBackup(String json, String passphrase) throws Exception { return plant.encryptBackup(json, passphrase); }
    public String decryptBackup(String envelopeText, String passphrase) throws Exception { return plant.decryptBackup(envelopeText, passphrase); }

    public String diagnosticsReport() { return plant.diagnosticsReport(); }
    public String riskLevel() { return plant.riskLevel(); }
    public int riskScore() { return plant.riskScore(); }
    public boolean isHardBlocked() { return plant.isHardBlocked(); }
    public void checkpointForeground() { plant.checkpointForeground(); }
    public void recordObscuredTouch() { plant.recordObscuredTouch(); }
}
