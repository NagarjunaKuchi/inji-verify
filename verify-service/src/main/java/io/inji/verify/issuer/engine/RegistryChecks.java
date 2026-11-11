package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;
import io.inji.verify.issuer.model.IssuerMetadata;
import io.inji.verify.issuer.registry.RegistryLookup;

import java.util.Optional;

/** Shared handling for checks that depend on registry metadata. */
final class RegistryChecks {
    private RegistryChecks() {
    }

    /** Metadata if the registry has the issuer. */
    static Optional<IssuerMetadata> metadata(VerificationContext ctx) {
        if (!ctx.registryConfigured || !ctx.canQueryRegistry()) return Optional.empty();
        return ctx.registry() instanceof RegistryLookup.Found f ? Optional.of(f.metadata()) : Optional.empty();
    }

    /** Result to use when metadata is unavailable: inconclusive for infrastructure, not-evaluated otherwise. */
    static CheckResult unmet(VerificationContext ctx, CheckId id) {
        if (!ctx.registryConfigured) {
            return CheckResult.inconclusive(id, "REGISTRY_NOT_CONFIGURED", "No trust registry is configured, so this could not be checked.");
        }
        if (!ctx.canQueryRegistry()) return CheckResult.notEvaluated(id, "Not evaluated because the issuer identifier is not usable.");
        RegistryLookup r = ctx.registry();
        if (r instanceof RegistryLookup.Unavailable u) {
            return CheckResult.inconclusive(id, u.reasonCode(), "The trust registry could not be consulted. This does not indicate a problem with the issuer.");
        }
        return CheckResult.notEvaluated(id, "Not evaluated because the issuer is not listed in the trust registry.");
    }
}
