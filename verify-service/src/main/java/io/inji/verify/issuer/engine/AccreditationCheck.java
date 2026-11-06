package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.model.Accreditation;
import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;
import io.inji.verify.issuer.model.LifecycleStatus;

public final class AccreditationCheck implements IssuerCheck {
    @Override
    public CheckId id() {
        return CheckId.ACCREDITATION_VALID;
    }

    @Override
    public CheckResult run(VerificationContext ctx) {
        var meta = RegistryChecks.metadata(ctx);
        if (meta.isEmpty()) return RegistryChecks.unmet(ctx, id());
        var accreditations = meta.get().accreditations();
        if (accreditations.isEmpty()) return CheckResult.fail(id(), "NO_ACCREDITATION", "The issuer has no accreditation on record.");
        boolean expired = false, notActive = false, notYet = false;
        for (Accreditation a : accreditations) {
            if (a.status() != LifecycleStatus.ACTIVE) {
                notActive = true;
            } else if (a.validUntil() != null && !ctx.now.minus(ctx.clockSkew).isBefore(a.validUntil())) {
                expired = true;
            } else if (a.validFrom() != null && ctx.now.plus(ctx.clockSkew).isBefore(a.validFrom())) {
                notYet = true;
            } else {
                return CheckResult.pass(id(), "ACCREDITATION_VALID", "The issuer holds a valid accreditation.");
            }
        }
        if (expired) return CheckResult.fail(id(), "ACCREDITATION_EXPIRED", "The issuer's accreditation has expired.");
        if (notYet) return CheckResult.fail(id(), "ACCREDITATION_NOT_YET_VALID", "The issuer's accreditation is not valid yet.");
        return CheckResult.fail(id(), notActive ? "ACCREDITATION_NOT_ACTIVE" : "NO_ACCREDITATION", "The issuer's accreditation is not active.");
    }
}
