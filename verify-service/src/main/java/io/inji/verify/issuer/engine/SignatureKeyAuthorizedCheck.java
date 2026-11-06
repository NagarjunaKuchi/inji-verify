package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.did.DidResolution;
import io.inji.verify.issuer.identifier.IssuerIdentifier;
import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;
import io.inji.verify.issuer.model.CheckStatus;

/** The matched key must be authorised for credential assertion (DID {@code assertionMethod}) and the proof must say so. */
public final class SignatureKeyAuthorizedCheck implements IssuerCheck {

    @Override
    public CheckId id() {
        return CheckId.SIGNATURE_KEY_AUTHORIZED;
    }

    @Override
    public CheckResult run(VerificationContext ctx) {
        CheckResult key = ctx.results.get(CheckId.PUBLIC_KEY_VALID);
        if (key == null || key.status() != CheckStatus.PASS) {
            return CheckResult.notEvaluated(id(), "Not evaluated because the signing key could not be tied to the issuer.");
        }
        if (ctx.identifier.type() == IssuerIdentifier.Type.HTTPS_URL) {
            return CheckResult.pass(id(), "KEY_REGISTERED_FOR_ISSUER", "The signing key is registered by the trust registry for this issuer.");
        }
        String purpose = ctx.credential.proofPurpose();
        if (purpose != null && !"assertionMethod".equals(purpose)) {
            return CheckResult.fail(id(), "PROOF_PURPOSE_MISMATCH", "The credential was signed for a purpose other than issuing credentials.");
        }
        var doc = ((DidResolution.Resolved) ctx.did()).document();
        return doc.assertionMethod().contains(ctx.matchedMethodId)
                ? CheckResult.pass(id(), "KEY_AUTHORIZED_FOR_ASSERTION", "The issuer authorises this key to issue credentials.")
                : CheckResult.fail(id(), "KEY_NOT_AUTHORIZED_FOR_ASSERTION", "The issuer has not authorised this key to issue credentials.");
    }
}
