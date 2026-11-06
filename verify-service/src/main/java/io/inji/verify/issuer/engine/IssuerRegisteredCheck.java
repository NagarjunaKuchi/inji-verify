package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;
import io.inji.verify.issuer.registry.RegistryLookup;

public final class IssuerRegisteredCheck implements IssuerCheck {
    @Override
    public CheckId id() {
        return CheckId.ISSUER_REGISTERED;
    }

    @Override
    public CheckResult run(VerificationContext ctx) {
        if (!ctx.registryConfigured || !ctx.canQueryRegistry()) return RegistryChecks.unmet(ctx, id());
        return switch (ctx.registry()) {
            case RegistryLookup.Found f -> CheckResult.pass(id(), "ISSUER_REGISTERED", "The issuer is listed in the trust registry.");
            case RegistryLookup.NotFound n -> CheckResult.fail(id(), "ISSUER_NOT_REGISTERED", "The issuer is not listed in the trust registry.");
            case RegistryLookup.Unavailable u -> RegistryChecks.unmet(ctx, id());
        };
    }
}
