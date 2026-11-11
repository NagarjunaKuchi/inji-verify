package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.did.DidResolution;
import io.inji.verify.issuer.did.DidResolvers;
import io.inji.verify.issuer.identifier.IssuerIdentifier;
import io.inji.verify.issuer.metadata.IssuerMetadataService;
import io.inji.verify.issuer.model.Accreditation;
import io.inji.verify.issuer.model.Authenticity;
import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;
import io.inji.verify.issuer.model.CheckStatus;
import io.inji.verify.issuer.model.CredentialIssuerContext;
import io.inji.verify.issuer.model.DisplayStatus;
import io.inji.verify.issuer.model.IssuerMetadata;
import io.inji.verify.issuer.model.IssuerVerificationResult;
import io.inji.verify.issuer.model.LifecycleStatus;
import io.inji.verify.issuer.model.OrganizationalTrust;
import io.inji.verify.issuer.model.TrustStatus;
import io.inji.verify.issuer.policy.TrustEvaluation;
import io.inji.verify.issuer.policy.TrustPolicy;
import io.inji.verify.issuer.policy.TrustPolicyEngine;
import io.inji.verify.issuer.registry.RegistryLookup;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Runs the independent checks and combines them under the active trust policy. It answers two separate
 * questions: cryptographic authenticity (did the key holder behind the issuer identifier sign this?) and
 * organisational trust (does an independent source say this issuer may issue this credential?).
 */
public final class IssuerVerificationEngine {

    private final DidResolvers didResolvers;
    private final IssuerMetadataService metadataService;
    private final TrustPolicyEngine policyEngine;
    private final TrustPolicy policy;
    private final List<IssuerCheck> checks;
    private final Clock clock;
    private final Duration clockSkew;

    public IssuerVerificationEngine(DidResolvers didResolvers, IssuerMetadataService metadataService, TrustPolicyEngine policyEngine,
                                    TrustPolicy policy, Clock clock, Duration clockSkew) {
        this(didResolvers, metadataService, policyEngine, policy, defaultChecks(), clock, clockSkew);
    }

    public IssuerVerificationEngine(DidResolvers didResolvers, IssuerMetadataService metadataService, TrustPolicyEngine policyEngine,
                                    TrustPolicy policy, List<IssuerCheck> checks, Clock clock, Duration clockSkew) {
        this.didResolvers = didResolvers;
        this.metadataService = metadataService;
        this.policyEngine = policyEngine;
        this.policy = policy;
        this.checks = List.copyOf(checks);
        this.clock = clock;
        this.clockSkew = clockSkew;
    }

    public static List<IssuerCheck> defaultChecks() {
        return List.of(new IssuerIdentifierCheck(), new DidResolutionCheck(), new DidDocumentCheck(), new PublicKeyCheck(),
                new SignatureKeyAuthorizedCheck(), new IssuerRegisteredCheck(), new IssuerActiveCheck(), new AccreditationCheck(),
                new CredentialTypeAuthorizedCheck(), new TrustFrameworkCheck());
    }

    public IssuerVerificationResult verify(CredentialIssuerContext credential) {
        IssuerIdentifier identifier = IssuerIdentifier.parse(credential.issuerId());
        VerificationContext ctx = new VerificationContext(credential, identifier, policy, clock.instant(), clockSkew,
                metadataService.isRegistryConfigured(), () -> didResolvers.resolve(identifier),
                () -> metadataService.lookup(identifier.value(), credential.credentialTypes()));

        for (IssuerCheck check : checks) {
            CheckResult result;
            try {
                result = check.run(ctx);
            } catch (RuntimeException e) {
                result = CheckResult.inconclusive(check.id(), "INTERNAL_ERROR", "This check could not be completed.");
            }
            ctx.results.put(check.id(), result);
        }
        return buildResult(ctx);
    }

    /** Result for cases where no checks could be run at all (e.g. unsupported credential format). */
    public IssuerVerificationResult inconclusive(String issuerId, String reasonCode, String message) {
        return new IssuerVerificationResult(issuerId, null, null, null, null, TrustStatus.INCONCLUSIVE, DisplayStatus.VERIFICATION_INCONCLUSIVE,
                policy.name(), Authenticity.INCONCLUSIVE, OrganizationalTrust.NOT_EVALUATED,
                List.of(CheckResult.inconclusive(CheckId.ISSUER_IDENTIFIER_VALID, reasonCode, message)), null, null, clock.instant(), List.of(reasonCode));
    }

    private IssuerVerificationResult buildResult(VerificationContext ctx) {
        TrustEvaluation eval = policyEngine.evaluate(policy, ctx.results);
        IssuerMetadata meta = ctx.registryConfigured && ctx.canQueryRegistry() && ctx.registry() instanceof RegistryLookup.Found f ? f.metadata() : null;

        return new IssuerVerificationResult(
                ctx.identifier.value() != null ? ctx.identifier.value() : ctx.credential.issuerId(),
                meta == null ? null : meta.displayName(),
                meta == null ? null : meta.legalName(),
                meta == null ? null : meta.organizationType(),
                meta == null ? null : meta.jurisdiction(),
                eval.status(), eval.displayStatus(), policy.name(),
                authenticity(ctx), organizationalTrust(ctx),
                new ArrayList<>(ctx.results.values()),
                accreditationSummary(meta, ctx),
                registrySummary(ctx),
                clock.instant(), eval.failureReasons());
    }

    private Authenticity authenticity(VerificationContext ctx) {
        boolean inconclusive = false;
        for (CheckId id : CheckId.values()) {
            if (!id.isCryptographic()) continue;
            CheckResult r = ctx.results.get(id);
            if (r == null) {
                inconclusive = true;
                continue;
            }
            if (r.status() == CheckStatus.FAIL) return Authenticity.FAILED;
            if (r.status() == CheckStatus.INCONCLUSIVE || r.status() == CheckStatus.NOT_EVALUATED) inconclusive = true;
        }
        return inconclusive ? Authenticity.INCONCLUSIVE : Authenticity.VERIFIED;
    }

    private OrganizationalTrust organizationalTrust(VerificationContext ctx) {
        if (!ctx.registryConfigured) return OrganizationalTrust.NOT_EVALUATED;
        Set<CheckId> relevant = EnumSet.of(CheckId.ISSUER_REGISTERED, CheckId.ISSUER_ACTIVE, CheckId.CREDENTIAL_TYPE_AUTHORIZED);
        if (ctx.policy.isRequired(CheckId.ACCREDITATION_VALID)) relevant.add(CheckId.ACCREDITATION_VALID);
        if (ctx.policy.isRequired(CheckId.TRUST_FRAMEWORK_VALID)) relevant.add(CheckId.TRUST_FRAMEWORK_VALID);
        boolean inconclusive = false;
        for (CheckId id : relevant) {
            CheckResult r = ctx.results.get(id);
            if (r == null) continue;
            if (r.status() == CheckStatus.FAIL) return OrganizationalTrust.UNTRUSTED;
            if (r.status() == CheckStatus.INCONCLUSIVE || r.status() == CheckStatus.NOT_EVALUATED) inconclusive = true;
        }
        return inconclusive ? OrganizationalTrust.INCONCLUSIVE : OrganizationalTrust.TRUSTED;
    }

    private IssuerVerificationResult.AccreditationSummary accreditationSummary(IssuerMetadata meta, VerificationContext ctx) {
        if (meta == null || meta.accreditations().isEmpty()) return null;
        Accreditation best = meta.accreditations().get(0);
        for (Accreditation a : meta.accreditations()) {
            if (a.status() == LifecycleStatus.ACTIVE && (a.validUntil() == null || ctx.now.isBefore(a.validUntil()))) {
                best = a;
                break;
            }
        }
        boolean expired = best.validUntil() != null && !ctx.now.isBefore(best.validUntil());
        String status = expired && best.status() == LifecycleStatus.ACTIVE ? "EXPIRED" : best.status().name();
        return new IssuerVerificationResult.AccreditationSummary(status, best.validFrom(), best.validUntil());
    }

    private IssuerVerificationResult.RegistrySummary registrySummary(VerificationContext ctx) {
        if (!ctx.registryConfigured) return new IssuerVerificationResult.RegistrySummary(null, "NOT_CONFIGURED");
        if (!ctx.canQueryRegistry()) return null;
        return switch (ctx.registry()) {
            case RegistryLookup.Found f -> new IssuerVerificationResult.RegistrySummary(f.registryId(), "VERIFIED");
            case RegistryLookup.NotFound n -> new IssuerVerificationResult.RegistrySummary(n.registryId(), "NOT_FOUND");
            case RegistryLookup.Unavailable u -> new IssuerVerificationResult.RegistrySummary(u.registryId(), "UNAVAILABLE");
        };
    }
}
