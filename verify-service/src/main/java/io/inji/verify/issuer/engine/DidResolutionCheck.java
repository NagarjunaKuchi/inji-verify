package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.did.DidResolution;
import io.inji.verify.issuer.identifier.IssuerIdentifier;
import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;

public final class DidResolutionCheck implements IssuerCheck {
    @Override
    public CheckId id() {
        return CheckId.DID_RESOLUTION;
    }

    @Override
    public CheckResult run(VerificationContext ctx) {
        IssuerIdentifier.Type t = ctx.identifier.type();
        if (t == IssuerIdentifier.Type.HTTPS_URL) return CheckResult.notApplicable(id(), "The issuer is not identified by a DID.");
        if (!ctx.identifier.isDid()) return CheckResult.notEvaluated(id(), "Not evaluated because the issuer identifier is not usable.");
        DidResolution r = ctx.did();
        if (r instanceof DidResolution.Resolved || r instanceof DidResolution.Malformed) {
            return CheckResult.pass(id(), "DID_RESOLVED", "The issuer DID document was retrieved.");
        }
        if (r instanceof DidResolution.NotFound) return CheckResult.fail(id(), "DID_NOT_FOUND", "The issuer DID could not be found.");
        if (r instanceof DidResolution.Blocked) return CheckResult.fail(id(), "DID_ENDPOINT_NOT_PERMITTED", "The issuer DID points to an endpoint this verifier does not permit.");
        if (r instanceof DidResolution.Unsupported) return CheckResult.inconclusive(id(), "UNSUPPORTED_DID_METHOD", "This DID method is not supported by this verifier.");
        String code = ((DidResolution.Unavailable) r).reasonCode();
        return CheckResult.inconclusive(id(), code, "The issuer DID could not be retrieved right now. This does not indicate a problem with the issuer.");
    }
}
