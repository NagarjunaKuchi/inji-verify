package io.inji.verify.issuer.model;

public enum CheckStatus {
    /** Positive evidence the check holds. */
    PASS,
    /** Positive evidence the check does not hold (e.g. issuer revoked, key not in DID document). */
    FAIL,
    /** Could not be determined because of an infrastructure/limitation problem. Never proof of malice. */
    INCONCLUSIVE,
    /** Could not be evaluated because a prerequisite check did not pass. */
    NOT_EVALUATED,
    /** Check does not apply to this kind of issuer (e.g. DID resolution for an https issuer). */
    NOT_APPLICABLE
}
