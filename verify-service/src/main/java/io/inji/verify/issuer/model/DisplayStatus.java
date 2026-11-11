package io.inji.verify.issuer.model;

/** Fine-grained status for the UI. {@link TrustStatus} stays the 3-valued machine decision. */
public enum DisplayStatus {
    TRUSTED_ISSUER,
    UNTRUSTED_ISSUER,
    ISSUER_NOT_FOUND,
    ISSUER_SUSPENDED,
    ISSUER_REVOKED,
    VERIFICATION_INCONCLUSIVE
}
