package io.inji.verify.issuer.model;

import java.util.Objects;

/**
 * Outcome of a single check. {@code reasonCode} is a stable machine-readable code and {@code message} a
 * safe, user-displayable explanation. Neither may contain internal URLs, IP addresses or exception text.
 */
public record CheckResult(CheckId id, CheckStatus status, String reasonCode, String message) {
    public CheckResult {
        Objects.requireNonNull(id);
        Objects.requireNonNull(status);
    }

    public static CheckResult pass(CheckId id, String reasonCode, String message) {
        return new CheckResult(id, CheckStatus.PASS, reasonCode, message);
    }

    public static CheckResult fail(CheckId id, String reasonCode, String message) {
        return new CheckResult(id, CheckStatus.FAIL, reasonCode, message);
    }

    public static CheckResult inconclusive(CheckId id, String reasonCode, String message) {
        return new CheckResult(id, CheckStatus.INCONCLUSIVE, reasonCode, message);
    }

    public static CheckResult notEvaluated(CheckId id, String message) {
        return new CheckResult(id, CheckStatus.NOT_EVALUATED, "PREREQUISITE_NOT_SATISFIED", message);
    }

    public static CheckResult notApplicable(CheckId id, String message) {
        return new CheckResult(id, CheckStatus.NOT_APPLICABLE, "NOT_APPLICABLE", message);
    }
}
