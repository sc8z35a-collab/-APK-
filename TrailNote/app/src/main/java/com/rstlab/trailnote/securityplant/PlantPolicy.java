package com.rstlab.trailnote.securityplant;

final class PlantPolicy {
    enum Action {
        OPEN_VAULT,
        READ_DATA,
        WRITE_DATA,
        EXPORT_BACKUP,
        IMPORT_BACKUP,
        CHANGE_PIN,
        DIAGNOSTICS
    }

    static final class Decision {
        final boolean allowed;
        final String mode;
        final String reason;

        Decision(boolean allowed, String mode, String reason) {
            this.allowed = allowed;
            this.mode = mode;
            this.reason = reason;
        }
    }

    Decision decide(ThreatScanner.Report report, Action action, boolean ledgerIntegrityOk) {
        if (!ledgerIntegrityOk || report.criticalTamper) {
            return action == Action.DIAGNOSTICS
                    ? new Decision(true, "CRITICAL", "Tamper evidence detected; diagnostics only")
                    : new Decision(false, "CRITICAL", "Integrity policy blocked the operation");
        }

        int score = report.score;
        if (score >= 95) {
            return action == Action.DIAGNOSTICS
                    ? new Decision(true, "CRITICAL", "Very high runtime risk")
                    : new Decision(false, "CRITICAL", "Runtime attack risk is too high");
        }
        if (score >= 70) {
            boolean readOnly = action == Action.READ_DATA || action == Action.DIAGNOSTICS;
            return new Decision(readOnly, "HIGH", readOnly
                    ? "High-risk environment: restricted read-only mode"
                    : "High-risk environment blocks sensitive mutations");
        }
        if (score >= 45) {
            boolean restricted = action == Action.CHANGE_PIN || action == Action.EXPORT_BACKUP || action == Action.IMPORT_BACKUP;
            return new Decision(!restricted, "ELEVATED", restricted
                    ? "Elevated environment risk blocks key/backup operations"
                    : "Elevated environment risk");
        }
        if (score >= 20) return new Decision(true, "GUARDED", "Risk signals present; checkpoints remain active");
        return new Decision(true, "NORMAL", "No material runtime attack signal");
    }
}
