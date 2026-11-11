package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;

public final class IssuerIdentifierCheck implements IssuerCheck {
    @Override
    public CheckId id() {
        return CheckId.ISSUER_IDENTIFIER_VALID;
    }

    @Override
    public CheckResult run(VerificationContext ctx) {
        var id = ctx.identifier;
        return switch (id.type()) {
            case DID_WEB, DID_JWK, HTTPS_URL -> CheckResult.pass(id() , "ISSUER_IDENTIFIER_VALID", "The issuer identifier is well-formed and supported.");
            case DID_UNSUPPORTED_METHOD, UNSUPPORTED_SCHEME -> CheckResult.inconclusive(id(), id.reasonCode(), "This type of issuer identifier is not supported by this verifier.");
            case INVALID -> CheckResult.fail(id(), id.reasonCode(), "The issuer identifier is missing or malformed.");
        };
    }
}
