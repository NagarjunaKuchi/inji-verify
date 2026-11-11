package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;
import io.inji.verify.issuer.model.IssuerMetadata;

/**
 * Lifecycle and validity of the issuer at verification time (conservative: an issuer revoked today does not
 * vouch for credentials, regardless of when they were issued).
 */
public final class IssuerActiveCheck implements IssuerCheck {
    @Override
    public CheckId id() {
        return CheckId.ISSUER_ACTIVE;
    }

    @Override
    public CheckResult run(VerificationContext ctx) {
        var meta = RegistryChecks.metadata(ctx);
        if (meta.isEmpty()) return RegistryChecks.unmet(ctx, id());
        IssuerMetadata m = meta.get();
        switch (m.status()) {
            case REVOKED:
                return CheckResult.fail(id(), "ISSUER_REVOKED", "The issuer's registration has been revoked.");
            case SUSPENDED:
                return CheckResult.fail(id(), "ISSUER_SUSPENDED", "The issuer is currently suspended.");
            case DEACTIVATED:
                return CheckResult.fail(id(), "ISSUER_DEACTIVATED", "The issuer has been deactivated.");
            default:
                break;
        }
        if (m.validFrom() != null && ctx.now.plus(ctx.clockSkew).isBefore(m.validFrom())) {
            return CheckResult.fail(id(), "ISSUER_NOT_YET_VALID", "The issuer's registration is not valid yet.");
        }
        if (m.validUntil() != null && !ctx.now.minus(ctx.clockSkew).isBefore(m.validUntil())) {
            return CheckResult.fail(id(), "ISSUER_VALIDITY_EXPIRED", "The issuer's registration has expired.");
        }
        return CheckResult.pass(id(), "ISSUER_ACTIVE", "The issuer is active.");
    }
}
