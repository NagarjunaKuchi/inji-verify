package io.inji.verify.issuer.model;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Canonical issuer metadata, independent of whichever trust registry supplied it.
 * All collections are never null.
 */
public record IssuerMetadata(
        String issuerId,
        String displayName,
        String legalName,
        String organizationType,
        String jurisdiction,
        LifecycleStatus status,
        Instant validFrom,
        Instant validUntil,
        List<Accreditation> accreditations,
        Set<String> trustFrameworks,
        Set<String> authorizedCredentialTypes,
        Set<String> keyThumbprints,
        Instant asOf) {

    public IssuerMetadata {
        accreditations = accreditations == null ? List.of() : List.copyOf(accreditations);
        trustFrameworks = trustFrameworks == null ? Set.of() : Set.copyOf(trustFrameworks);
        authorizedCredentialTypes = authorizedCredentialTypes == null ? Set.of() : Set.copyOf(authorizedCredentialTypes);
        keyThumbprints = keyThumbprints == null ? Set.of() : Set.copyOf(keyThumbprints);
    }
}
