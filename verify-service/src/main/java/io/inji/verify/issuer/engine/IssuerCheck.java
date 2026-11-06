package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;

/** One independently testable verification check. Implementations must be side-effect free and must not throw. */
public interface IssuerCheck {
    CheckId id();

    CheckResult run(VerificationContext ctx);
}
