package com.rstlab.trailnote.securityplant;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.view.WindowManager;

import com.rstlab.trailnote.securityplant.distribution.DistributionTrustPlant;

/**
 * Security Container Plant: central coordinator for multiple independent guards.
 *
 * Sensitive operations must satisfy distribution identity, component integrity,
 * runtime RASP, storage/ledger integrity and UI hardening checks before crypto is used.
 */
public final class SecurityContainerPlant {
    private static final long REPORT_CACHE_MS = 2_000L;

    private final CryptoPlant crypto;
    private final ThreatScanner scanner;
    private final DistributionTrustPlant distributionTrust;
    private final ComponentIntegrityPlant componentIntegrity;
    private final PlantPolicy policy;
    private final TamperLedger ledger;
    private final GuardMesh guardMesh;
    private ThreatScanner.Report lastReport;
    private long lastReportAt;
    private final boolean ledgerIntegrityOkAtBoot;

    public SecurityContainerPlant(Context context) {
        Context app = context.getApplicationContext();
        crypto = new CryptoPlant(app);
        scanner = new ThreatScanner(app);
        distributionTrust = new DistributionTrustPlant(app);
        componentIntegrity = new ComponentIntegrityPlant(app);
        policy = new PlantPolicy();
        ledger = new TamperLedger(app);
        ledgerIntegrityOkAtBoot = ledger.verify();
        hardenWindow(context);
        guardMesh = new GuardMesh(context, crypto, componentIntegrity);

        ThreatScanner.Report boot = report(true);
        DistributionTrustPlant.Report dist = distributionTrust.verify();
        GuardMesh.Report mesh = guardMesh.evaluate(boot, dist, ledgerIntegrityOk());
        ledger.append("plant_boot", "Security Container Plant v4 / " + dist.level + " / mesh=" + mesh.compact(),
                Math.max(boot.score, mesh.score));
        if (dist.critical || mesh.critical) {
            crypto.lockSession();
            ledger.append("boot_trust_block", joinSignals(dist) + "/" + joinMesh(mesh), 100);
        }
    }

    public boolean hasPin() { return crypto.hasPin(); }

    public void setPin(String pin) throws Exception {
        enforce(PlantPolicy.Action.CHANGE_PIN);
        crypto.setPin(pin);
        ledger.append("pin_updated", "PIN verifier/root wrapping updated", effectiveRisk());
    }

    public boolean verifyPin(String pin) throws Exception {
        enforce(PlantPolicy.Action.OPEN_VAULT);
        boolean ok = crypto.verifyPin(pin);
        ThreatScanner.Report r = report(true);
        DistributionTrustPlant.Report d = distributionTrust.verify();
        GuardMesh.Report mesh = guardMesh.evaluate(r, d, ledgerIntegrityOk());
        ledger.append(ok ? "vault_unlock" : "vault_unlock_failed",
                ok ? "hardware/root key unwrapped" : "authentication failed", Math.max(r.score, mesh.score));
        return ok;
    }

    public void lockSession() {
        crypto.lockSession();
        ledger.append("vault_lock", "session root key zeroized", effectiveRisk());
    }

    public boolean isSessionUnlocked() { return crypto.isSessionUnlocked(); }
    public boolean isLockedOut() { return crypto.isLockedOut(); }
    public long lockoutUntil() { return crypto.lockoutUntil(); }
    public int failedAttempts() { return crypto.failedAttempts(); }

    public String loadEntries(SharedPreferences legacyPrefs, String legacyKey) throws Exception {
        enforce(PlantPolicy.Action.READ_DATA);
        String result = crypto.loadEntries(legacyPrefs, legacyKey);
        ledger.append("vault_read", crypto.hierarchyConfigured() ? "H4 compartmentalized workspace opened" : "legacy workspace opened",
                effectiveRisk());
        return result;
    }

    public void saveEntries(String json) throws Exception {
        enforce(PlantPolicy.Action.WRITE_DATA);
        crypto.saveEntries(json);
        ledger.append("vault_write", "H4 domain-encrypted workspace committed", effectiveRisk());
    }

    public boolean hasEncryptedData() { return crypto.hasEncryptedData(); }

    public String encryptBackup(String json, String passphrase) throws Exception {
        enforce(PlantPolicy.Action.EXPORT_BACKUP);
        String result = crypto.encryptBackup(json, passphrase);
        ledger.append("backup_export", "encrypted Security Plant v4 backup created", effectiveRisk());
        return result;
    }

    public String decryptBackup(String envelopeText, String passphrase) throws Exception {
        enforce(PlantPolicy.Action.IMPORT_BACKUP);
        String result = crypto.decryptBackup(envelopeText, passphrase);
        ledger.append("backup_import", "authenticated backup accepted", effectiveRisk());
        return result;
    }

    public String securitySummary() {
        ThreatScanner.Report r = report(false);
        DistributionTrustPlant.Report d = distributionTrust.verify();
        GuardMesh.Report mesh = guardMesh.evaluate(r, d, ledgerIntegrityOk());
        return crypto.summary() + " / RASP " + r.level() + " " + r.score + "/100 / "
                + d.level + " / GuardMesh " + mesh.compact();
    }

    public boolean isHardBlocked() {
        ThreatScanner.Report r = report(true);
        DistributionTrustPlant.Report dist = distributionTrust.verify();
        GuardMesh.Report mesh = guardMesh.evaluate(r, dist, ledgerIntegrityOk());
        if (dist.critical || mesh.critical) return true;
        PlantPolicy.Decision d = policy.decide(r, PlantPolicy.Action.OPEN_VAULT, ledgerIntegrityOk());
        return !d.allowed;
    }

    public String riskLevel() {
        ThreatScanner.Report r = report(false);
        DistributionTrustPlant.Report dist = distributionTrust.verify();
        GuardMesh.Report mesh = guardMesh.evaluate(r, dist, ledgerIntegrityOk());
        if (dist.critical || mesh.critical) return "CRITICAL";
        if (Math.max(r.score, mesh.score) >= 70) return "HIGH";
        if (Math.max(r.score, mesh.score) >= 45) return "ELEVATED";
        if (Math.max(r.score, mesh.score) >= 20) return "GUARDED";
        return "NORMAL";
    }

    public int riskScore() {
        ThreatScanner.Report r = report(false);
        DistributionTrustPlant.Report dist = distributionTrust.verify();
        GuardMesh.Report mesh = guardMesh.evaluate(r, dist, ledgerIntegrityOk());
        return dist.critical || mesh.critical ? 100 : Math.max(r.score, mesh.score);
    }

    public String diagnosticsReport() {
        ThreatScanner.Report r = report(true);
        DistributionTrustPlant.Report dist = distributionTrust.verify();
        ComponentIntegrityPlant.Report components = componentIntegrity.verify(dist.trusted);
        GuardMesh.Report mesh = guardMesh.evaluate(r, dist, ledgerIntegrityOk());
        PlantPolicy.Decision d = policy.decide(r, PlantPolicy.Action.DIAGNOSTICS, ledgerIntegrityOk());
        StringBuilder sb = new StringBuilder();
        sb.append("Security Container Plant v4\n");
        sb.append("mode=").append(dist.critical || mesh.critical ? "CRITICAL" : d.mode)
                .append(" risk=").append(dist.critical || mesh.critical ? 100 : Math.max(r.score, mesh.score)).append("/100\n");
        sb.append("hardwareRoot=").append(crypto.hardwareBackedSummary()).append("\n");
        sb.append("workspaceCrypto=").append(crypto.hierarchyConfigured() ? "H4-DOMAIN-HIERARCHY" : "LEGACY-MIGRATION").append("\n");
        sb.append("distribution=").append(dist.level).append("\n");
        sb.append("distributionSigner=").append(dist.currentSignerSha256).append("\n");
        sb.append("distributionApkSha256=").append(dist.apkSha256).append("\n");
        sb.append("distributionVersion=").append(dist.versionCode).append("\n");
        sb.append("distributionSignals=").append(joinSignals(dist)).append("\n");
        sb.append("componentIntegrity=").append(components.compact()).append("\n");
        sb.append("componentSignals=").append(joinComponent(components)).append("\n");
        sb.append("guardMesh=").append(mesh.compact()).append("\n");
        sb.append("guardSignals=").append(joinMesh(mesh)).append("\n");
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
                Math.min(100, Math.max(r.score, effectiveRisk()) + 25));
    }

    public void recordSecurityEvent(String event, String detail) {
        ledger.append(event, detail, effectiveRisk());
    }

    private void enforce(PlantPolicy.Action action) throws SecurityException {
        DistributionTrustPlant.Report dist = distributionTrust.verify();
        ThreatScanner.Report r = report(true);
        boolean ledgerOk = ledgerIntegrityOk();
        GuardMesh.Report mesh = guardMesh.evaluate(r, dist, ledgerOk);

        if (dist.critical || mesh.critical) {
            crypto.lockSession();
            ledger.append("mesh_policy_block", action.name() + ":" + joinSignals(dist) + ":" + joinMesh(mesh), 100);
            throw new SecurityException("Security Container Plant: independent trust guards rejected operation");
        }

        PlantPolicy.Decision decision = policy.decide(r, action, ledgerOk);
        if (!decision.allowed) {
            crypto.lockSession();
            ledger.append("policy_block", action.name() + ":" + decision.reason, Math.max(80, Math.max(r.score, mesh.score)));
            throw new SecurityException("Security Container Plant: " + decision.reason);
        }
        if (r.score >= 45 || mesh.score >= 45) {
            ledger.append("risk_checkpoint", action.name() + ":" + decision.mode + ":mesh=" + mesh.score,
                    Math.max(r.score, mesh.score));
        }
    }

    private int effectiveRisk() {
        ThreatScanner.Report r = report(false);
        DistributionTrustPlant.Report d = distributionTrust.verify();
        GuardMesh.Report mesh = guardMesh.evaluate(r, d, ledgerIntegrityOk());
        return d.critical || mesh.critical ? 100 : Math.max(r.score, mesh.score);
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

    private static String joinMesh(GuardMesh.Report report) {
        if (report.signals.isEmpty()) return "none";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < report.signals.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(report.signals.get(i));
        }
        return sb.toString();
    }

    private static String joinComponent(ComponentIntegrityPlant.Report report) {
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
