package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;

public final class TrustFrameworkCheck implements IssuerCheck {
    @Override
    public CheckId id() {
        return CheckId.TRUST_FRAMEWORK_VALID;
    }

    @Override
    public CheckResult run(VerificationContext ctx) {
        var approved = ctx.policy.approvedTrustFrameworks();
        if (approved.isEmpty()) {
            // A policy that requires framework membership but approves no framework is misconfigured: fail closed.
            return ctx.policy.isRequired(id())
                    ? CheckResult.inconclusive(id(), "POLICY_MISCONFIGURED", "The trust policy requires a trust framework but none is configured.")
                    : CheckResult.notApplicable(id(), "No trust framework is required by the active policy.");
        }
        var meta = RegistryChecks.metadata(ctx);
        if (meta.isEmpty()) return RegistryChecks.unmet(ctx, id());
        return meta.get().trustFrameworks().stream().anyMatch(approved::contains)
                ? CheckResult.pass(id(), "TRUST_FRAMEWORK_MEMBER", "The issuer belongs to an approved trust framework.")
                : CheckResult.fail(id(), "TRUST_FRAMEWORK_NOT_APPROVED", "The issuer does not belong to an approved trust framework.");
    }
}
