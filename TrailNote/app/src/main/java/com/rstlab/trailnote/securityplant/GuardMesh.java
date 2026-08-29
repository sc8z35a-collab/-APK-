package com.rstlab.trailnote.securityplant;

import android.app.Activity;
import android.content.Context;
import android.view.View;
import android.view.WindowManager;

import com.rstlab.trailnote.securityplant.distribution.DistributionTrustPlant;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Security Plant multi-guard mesh.
 *
 * Five guards evaluate independent trust surfaces. The mesh then performs cross-
 * consistency checks so bypassing one central function is not enough to suppress
 * every security decision.
 */
final class GuardMesh {
    static final class Report {
        final boolean critical;
        final int score;
        final int passed;
        final int warned;
        final int failed;
        final List<String> signals;

        Report(boolean critical, int score, int passed, int warned, int failed, List<String> signals) {
            this.critical = critical;
            this.score = Math.max(0, Math.min(100, score));
            this.passed = passed;
            this.warned = warned;
            this.failed = failed;
            this.signals = Collections.unmodifiableList(signals);
        }

        String compact() {
            return (critical ? "BLOCKED" : score >= 45 ? "ELEVATED" : "OK")
                    + " pass=" + passed + " warn=" + warned + " fail=" + failed + " score=" + score;
        }
    }

    private static final int PASS = 0;
    private static final int WARN = 1;
    private static final int FAIL = 2;

    private final Context originalContext;
    private final CryptoPlant crypto;
    private final ComponentIntegrityPlant components;

    GuardMesh(Context originalContext, CryptoPlant crypto, ComponentIntegrityPlant components) {
        this.originalContext = originalContext;
        this.crypto = crypto;
        this.components = components;
    }

    Report evaluate(ThreatScanner.Report runtime,
                    DistributionTrustPlant.Report distribution,
                    boolean ledgerOk) {
        List<String> signals = new ArrayList<>();
        int passed = 0;
        int warned = 0;
        int failed = 0;
        int score = 0;

        int cryptoState = cryptoGuard(signals);
        if (cryptoState == PASS) passed++; else if (cryptoState == WARN) { warned++; score += 20; } else { failed++; score += 60; }

        int runtimeState = runtimeGuard(runtime, signals);
        if (runtimeState == PASS) passed++; else if (runtimeState == WARN) { warned++; score += 25; } else { failed++; score += 70; }

        int distributionState = distributionGuard(distribution, signals);
        if (distributionState == PASS) passed++; else if (distributionState == WARN) { warned++; score += 20; } else { failed++; score += 100; }

        int storageState = storageGuard(ledgerOk, distribution, signals);
        if (storageState == PASS) passed++; else if (storageState == WARN) { warned++; score += 25; } else { failed++; score += 100; }

        int uiState = uiGuard(signals);
        if (uiState == PASS) passed++; else if (uiState == WARN) { warned++; score += 12; } else { failed++; score += 45; }

        // Cross-guard consistency checks. These are intentionally redundant.
        if (distribution.trusted && distribution.critical) {
            failed++;
            score += 100;
            signals.add("mesh-inconsistent-distribution-state");
        }
        if (runtime.criticalTamper && distribution.trusted) {
            warned++;
            score += 35;
            signals.add("mesh-runtime-tamper-despite-valid-distribution");
        }
        if (crypto.hasEncryptedData() && !crypto.hierarchyConfigured()) {
            warned++;
            score += 18;
            signals.add("mesh-legacy-storage-awaiting-h4-migration");
        }

        boolean critical = distribution.critical || !ledgerOk || failed >= 2 || score >= 95;
        return new Report(critical, score, passed, warned, failed, signals);
    }

    private int cryptoGuard(List<String> signals) {
        String hardware = crypto.hardwareBackedSummary();
        if (hardware.contains("UNAVAILABLE")) {
            signals.add("crypto-guard-keystore-unavailable");
            return FAIL;
        }
        if (hardware.contains("STRONGBOX") && hardware.contains("/HW")) {
            signals.add("crypto-guard-strongbox");
            return PASS;
        }
        if (hardware.contains("/HW")) {
            signals.add("crypto-guard-tee-hardware");
            return PASS;
        }
        signals.add("crypto-guard-keystore-fallback");
        return WARN;
    }

    private static int runtimeGuard(ThreatScanner.Report runtime, List<String> signals) {
        if (runtime.criticalTamper || runtime.score >= 95) {
            signals.add("runtime-guard-critical");
            return FAIL;
        }
        if (runtime.score >= 45) {
            signals.add("runtime-guard-elevated");
            return WARN;
        }
        signals.add("runtime-guard-normal");
        return PASS;
    }

    private static int distributionGuard(DistributionTrustPlant.Report distribution, List<String> signals) {
        if (distribution.critical) {
            signals.add("distribution-guard-blocked");
            return FAIL;
        }
        if (!distribution.production) {
            signals.add("distribution-guard-diagnostic");
            return WARN;
        }
        signals.add("distribution-guard-production-trusted");
        return PASS;
    }

    private int storageGuard(boolean ledgerOk, DistributionTrustPlant.Report distribution, List<String> signals) {
        if (!ledgerOk) {
            signals.add("storage-guard-ledger-failed");
            return FAIL;
        }
        ComponentIntegrityPlant.Report component = components.verify(distribution.trusted);
        if (component.critical) {
            signals.add("storage-guard-component-integrity-failed");
            return FAIL;
        }
        if (!crypto.hierarchyConfigured() && crypto.hasEncryptedData()) {
            signals.add("storage-guard-legacy-format");
            return WARN;
        }
        signals.add("storage-guard-sealed");
        return PASS;
    }

    private int uiGuard(List<String> signals) {
        if (!(originalContext instanceof Activity)) {
            signals.add("ui-guard-no-activity-context");
            return WARN;
        }
        Activity activity = (Activity) originalContext;
        boolean secure = (activity.getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE) != 0;
        View decor = activity.getWindow().getDecorView();
        boolean obscuredFilter = decor.getFilterTouchesWhenObscured();
        if (!secure) {
            signals.add("ui-guard-flag-secure-missing");
            return FAIL;
        }
        if (!obscuredFilter) {
            signals.add("ui-guard-obscured-filter-missing");
            return WARN;
        }
        signals.add("ui-guard-hardened");
        return PASS;
    }
}
