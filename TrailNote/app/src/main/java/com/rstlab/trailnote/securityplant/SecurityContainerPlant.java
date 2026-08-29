package com.rstlab.trailnote.securityplant;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.view.WindowManager;

import com.rstlab.trailnote.securityplant.distribution.DistributionTrustPlant;

/**
 * Security Container Plant: the single security gateway for TrailNote.
 *
 * All vault reads/writes, authentication, backups and key mutations pass through
 * runtime threat evaluation, distribution identity verification and a tamper-evident ledger.
 */
public final class SecurityContainerPlant {
    private static final long REPORT_CACHE_MS = 2_000L;

    private final CryptoPlant crypto;
    private final ThreatScanner scanner;
    private final DistributionTrustPlant distributionTrust;
    private final PlantPolicy policy;
    private final TamperLedger ledger;
    private ThreatScanner.Report lastReport;
    private long lastReportAt;
    private final boolean ledgerIntegrityOkAtBoot;

    public SecurityContainerPlant(Context context) {
        Context app = context.getApplicationContext();
        crypto = new CryptoPlant(app);
        scanner = new ThreatScanner(app);
        distributionTrust = new DistributionTrustPlant(app);
        policy = new PlantPolicy();
        ledger = new TamperLedger(app);
        ledgerIntegrityOkAtBoot = ledger.verify();
        hardenWindow(context);
        ThreatScanner.Report boot = report(true);
        DistributionTrustPlant.Report dist = distributionTrust.verify();
        ledger.append("plant_boot", "Security Container Plant initialized / " + dist.level, boot.score);
        if (dist.critical) {
            crypto.lockSession();
            ledger.append("distribution_trust_block", joinSignals(dist), 100);
        }
    }

    public boolean hasPin() { return crypto.hasPin(); }

    public void setPin(String pin) throws Exception {
        enforce(PlantPolicy.Action.CHANGE_PIN);
        crypto.setPin(pin);
        ledger.append("pin_updated", "PIN verifier and key wrapping updated", report(false).score);
    }

    public boolean verifyPin(String pin) throws Exception {
        enforce(PlantPolicy.Action.OPEN_VAULT);
        boolean ok = crypto.verifyPin(pin);
        ThreatScanner.Report r = report(true);
        ledger.append(ok ? "vault_unlock" : "vault_unlock_failed",
                ok ? "session key unwrapped" : "authentication failed", r.score);
        return ok;
    }

    public void lockSession() {
        crypto.lockSession();
        ThreatScanner.Report r = report(false);
        ledger.append("vault_lock", "session master key zeroized", r.score);
    }

    public boolean isSessionUnlocked() { return crypto.isSessionUnlocked(); }
    public boolean isLockedOut() { return crypto.isLockedOut(); }
    public long lockoutUntil() { return crypto.lockoutUntil(); }
    public int failedAttempts() { return crypto.failedAttempts(); }

    public String loadEntries(SharedPreferences legacyPrefs, String legacyKey) throws Exception {
        enforce(PlantPolicy.Action.READ_DATA);
        return crypto.loadEntries(legacyPrefs, legacyKey);
    }

    public void saveEntries(String json) throws Exception {
        enforce(PlantPolicy.Action.WRITE_DATA);
        crypto.saveEntries(json);
        ledger.append("vault_write", "authenticated encrypted data committed", report(false).score);
    }

    public boolean hasEncryptedData() { return crypto.hasEncryptedData(); }

    public String encryptBackup(String json, String passphrase) throws Exception {
        enforce(PlantPolicy.Action.EXPORT_BACKUP);
        String result = crypto.encryptBackup(json, passphrase);
        ledger.append("backup_export", "encrypted Security Plant backup created", report(false).score);
        return result;
    }

    public String decryptBackup(String envelopeText, String passphrase) throws Exception {
        enforce(PlantPolicy.Action.IMPORT_BACKUP);
        String result = crypto.decryptBackup(envelopeText, passphrase);
        ledger.append("backup_import", "authenticated backup accepted", report(false).score);
        return result;
    }

    public String securitySummary() {
        ThreatScanner.Report r = report(false);
        DistributionTrustPlant.Report d = distributionTrust.verify();
        return crypto.summary() + " / RASP " + r.level() + " " + r.score + "/100 / "
                + d.level + " / HMAC audit chain";
    }

    public boolean isHardBlocked() {
        DistributionTrustPlant.Report dist = distributionTrust.verify();
        if (dist.critical) return true;
        PlantPolicy.Decision d = policy.decide(report(true), PlantPolicy.Action.OPEN_VAULT, ledgerIntegrityOk());
        return !d.allowed;
    }

    public String riskLevel() {
        DistributionTrustPlant.Report dist = distributionTrust.verify();
        return dist.critical ? "CRITICAL" : report(false).level();
    }

    public int riskScore() {
        return distributionTrust.verify().critical ? 100 : report(false).score;
    }

    public String diagnosticsReport() {
        ThreatScanner.Report r = report(true);
        DistributionTrustPlant.Report dist = distributionTrust.verify();
        PlantPolicy.Decision d = policy.decide(r, PlantPolicy.Action.DIAGNOSTICS, ledgerIntegrityOk());
        StringBuilder sb = new StringBuilder();
        sb.append("Security Container Plant\n");
        sb.append("mode=").append(dist.critical ? "CRITICAL" : d.mode)
                .append(" risk=").append(dist.critical ? 100 : r.score).append("/100\n");
        sb.append("distribution=").append(dist.level).append("\n");
        sb.append("distributionSigner=").append(dist.currentSignerSha256).append("\n");
        sb.append("distributionApkSha256=").append(dist.apkSha256).append("\n");
        sb.append("distributionVersion=").append(dist.versionCode).append("\n");
        sb.append("distributionSignals=").append(joinSignals(dist)).append("\n");
        sb.append("ledger=").append(ledgerIntegrityOk() ? "OK" : "FAILED").append("\n");
        sb.append("session=").append(crypto.isSessionUnlocked() ? "UNLOCKED" : "LOCKED").append("\n");
        sb.append("pin=").append(crypto.hasPin() ? "ENABLED" : "NOT_SET").append("\n");
        sb.append("raspSignals=");
        if (r.signals.isEmpty()) sb.append("none");
        else {
            for (int i = 0; i < r.signals.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append(r.signals.get(i));
            }
        }
        sb.append("\n").append(ledger.diagnosticSummary());
        return sb.toString();
    }

    public void checkpointForeground() throws SecurityException { enforce(PlantPolicy.Action.READ_DATA); }

    public void recordObscuredTouch() {
        ThreatScanner.Report r = report(true);
        ledger.append("obscured_touch", "touch rejected due to overlay/obscured window signal",
                Math.min(100, r.score + 25));
    }

    public void recordSecurityEvent(String event, String detail) {
        ThreatScanner.Report r = report(false);
        ledger.append(event, detail, r.score);
    }

    private void enforce(PlantPolicy.Action action) throws SecurityException {
        DistributionTrustPlant.Report dist = distributionTrust.verify();
        if (dist.critical) {
            crypto.lockSession();
            ledger.append("distribution_policy_block", action.name() + ":" + joinSignals(dist), 100);
            throw new SecurityException("Security Container Plant: distribution identity/integrity rejected");
        }

        ThreatScanner.Report r = report(true);
        boolean ledgerOk = ledgerIntegrityOk();
        PlantPolicy.Decision decision = policy.decide(r, action, ledgerOk);
        if (!decision.allowed) {
            crypto.lockSession();
            ledger.append("policy_block", action.name() + ":" + decision.reason, Math.max(80, r.score));
            throw new SecurityException("Security Container Plant: " + decision.reason);
        }
        if (r.score >= 45) {
            ledger.append("risk_checkpoint", action.name() + ":" + decision.mode, r.score);
        }
    }

    private synchronized ThreatScanner.Report report(boolean force) {
        long now = System.currentTimeMillis();
        if (force || lastReport == null || now - lastReportAt >= REPORT_CACHE_MS) {
            lastReport = scanner.scan();
            lastReportAt = now;
        }
        return lastReport;
    }

    private boolean ledgerIntegrityOk() { return ledgerIntegrityOkAtBoot && ledger.verify(); }

    private static String joinSignals(DistributionTrustPlant.Report report) {
        if (report.signals.isEmpty()) return "none";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < report.signals.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(report.signals.get(i));
        }
        return sb.toString();
    }

    private void hardenWindow(Context context) {
        if (!(context instanceof Activity)) return;
        Activity activity = (Activity) context;
        activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        activity.getWindow().getDecorView().setFilterTouchesWhenObscured(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            activity.getWindow().setHideOverlayWindows(true);
        }
    }
}
