package io.inji.verify.issuer.model;

/** Independent issuer verification checks. Order here is the evaluation/display order. */
public enum CheckId {
    ISSUER_IDENTIFIER_VALID,
    DID_RESOLUTION,
    DID_DOCUMENT_VALID,
    PUBLIC_KEY_VALID,
    SIGNATURE_KEY_AUTHORIZED,
    ISSUER_REGISTERED,
    ISSUER_ACTIVE,
    ACCREDITATION_VALID,
    CREDENTIAL_TYPE_AUTHORIZED,
    TRUST_FRAMEWORK_VALID;

    /** Checks that prove the credential was signed by the entity controlling the issuer identifier. */
    public boolean isCryptographic() {
        return ordinal() <= SIGNATURE_KEY_AUTHORIZED.ordinal();
    }
}
