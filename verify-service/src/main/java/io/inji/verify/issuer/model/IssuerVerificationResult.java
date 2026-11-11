package io.inji.verify.issuer.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;

/**
 * API/UI result. The two independent questions are reported separately in
 * {@code cryptographicAuthenticity} and {@code organizationalTrust}; {@code overallStatus} is the
 * outcome of the configured trust policy.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record IssuerVerificationResult(
        String issuerId,
        String issuerName,
        String legalName,
        String organizationType,
        String jurisdiction,
        TrustStatus overallStatus,
        DisplayStatus displayStatus,
        String policy,
        Authenticity cryptographicAuthenticity,
        OrganizationalTrust organizationalTrust,
        List<CheckResult> checks,
        AccreditationSummary accreditation,
        RegistrySummary trustRegistry,
        Instant verifiedAt,
        List<String> failureReasons) {

    public record AccreditationSummary(String status, Instant validFrom, Instant validUntil) {
    }

    public record RegistrySummary(String registryId, String status) {
    }
}
