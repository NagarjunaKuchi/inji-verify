package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.did.DidResolution;
import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;

public final class DidDocumentCheck implements IssuerCheck {
    @Override
    public CheckId id() {
        return CheckId.DID_DOCUMENT_VALID;
    }

    @Override
    public CheckResult run(VerificationContext ctx) {
        if (!ctx.identifier.isDid()) {
            return ctx.identifier.isSupported()
                    ? CheckResult.notApplicable(id(), "The issuer is not identified by a DID.")
                    : CheckResult.notEvaluated(id(), "Not evaluated because the issuer identifier is not usable.");
        }
        DidResolution r = ctx.did();
        if (r instanceof DidResolution.Resolved) return CheckResult.pass(id(), "DID_DOCUMENT_VALID", "The issuer DID document is well-formed.");
        if (r instanceof DidResolution.Malformed m) return CheckResult.fail(id(), "INVALID_DID_DOCUMENT", "The issuer DID document is malformed or inconsistent (" + m.reasonCode() + ").");
        return CheckResult.notEvaluated(id(), "Not evaluated because the issuer DID could not be retrieved.");
    }
}
