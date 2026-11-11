package io.inji.verify.issuer.policy;

import io.inji.verify.issuer.model.CheckId;

import java.util.EnumSet;
import java.util.Set;

/**
 * Declarative trust policy. {@code required} checks must PASS (or be NOT_APPLICABLE) for TRUSTED;
 * {@code optional} checks are reported but never decide the outcome, except that an issuer which a registry says is
 * suspended, revoked or deactivated is always untrusted. ISSUER_IDENTIFIER_VALID and SIGNATURE_KEY_AUTHORIZED are
 * always required: no policy can declare an issuer trusted without cryptographic binding to its identifier.
 */
public record TrustPolicy(String name, Set<CheckId> required, Set<CheckId> optional, Set<String> approvedTrustFrameworks) {

    public TrustPolicy {
        EnumSet<CheckId> req = required == null || required.isEmpty() ? EnumSet.noneOf(CheckId.class) : EnumSet.copyOf(required);
        req.add(CheckId.ISSUER_IDENTIFIER_VALID);
        req.add(CheckId.SIGNATURE_KEY_AUTHORIZED);
        required = Set.copyOf(req);
        optional = optional == null ? Set.of() : Set.copyOf(optional);
        approvedTrustFrameworks = approvedTrustFrameworks == null ? Set.of() : Set.copyOf(approvedTrustFrameworks);
    }

    public boolean isRequired(CheckId id) {
        return required.contains(id);
    }

    private static final Set<CheckId> CRYPTO = Set.of(CheckId.ISSUER_IDENTIFIER_VALID, CheckId.DID_RESOLUTION, CheckId.DID_DOCUMENT_VALID,
            CheckId.PUBLIC_KEY_VALID, CheckId.SIGNATURE_KEY_AUTHORIZED);

    /** Policy A: registered, active, accredited and authorised for this credential type. */
    public static TrustPolicy registryStrict() {
        var r = EnumSet.copyOf(CRYPTO);
        r.addAll(Set.of(CheckId.ISSUER_REGISTERED, CheckId.ISSUER_ACTIVE, CheckId.ACCREDITATION_VALID, CheckId.CREDENTIAL_TYPE_AUTHORIZED));
        return new TrustPolicy("A", r, Set.of(), Set.of());
    }

    /** Policy B: DID-based cryptographic issuer verification is sufficient; registry is advisory. */
    public static TrustPolicy cryptographicOnly() {
        return new TrustPolicy("B", CRYPTO, Set.of(CheckId.ISSUER_REGISTERED, CheckId.ISSUER_ACTIVE, CheckId.ACCREDITATION_VALID,
                CheckId.CREDENTIAL_TYPE_AUTHORIZED, CheckId.TRUST_FRAMEWORK_VALID), Set.of());
    }

    /** Policy C: member of an approved trust framework with valid accreditation. */
    public static TrustPolicy trustFramework(Set<String> approvedFrameworks) {
        var r = EnumSet.copyOf(CRYPTO);
        r.addAll(Set.of(CheckId.ISSUER_REGISTERED, CheckId.ISSUER_ACTIVE, CheckId.ACCREDITATION_VALID, CheckId.TRUST_FRAMEWORK_VALID));
        return new TrustPolicy("C", r, Set.of(CheckId.CREDENTIAL_TYPE_AUTHORIZED), approvedFrameworks);
    }

    /**
     * Policy D: registered and authorised for the credential type, nothing more. For registries that only answer
     * authorization questions (e.g. TRQP) and carry no lifecycle or accreditation data, which policy A would
     * therefore never be able to satisfy.
     */
    public static TrustPolicy authorizationOnly() {
        var r = EnumSet.copyOf(CRYPTO);
        r.addAll(Set.of(CheckId.ISSUER_REGISTERED, CheckId.CREDENTIAL_TYPE_AUTHORIZED));
        return new TrustPolicy("D", r, Set.of(CheckId.ISSUER_ACTIVE), Set.of());
    }
}
