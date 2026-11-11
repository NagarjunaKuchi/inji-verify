package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;

import java.util.List;

/** Every specific credential type claimed by the credential must be in the issuer's registered authorisations. */
public final class CredentialTypeAuthorizedCheck implements IssuerCheck {

    static final String WILDCARD = "*";

    @Override
    public CheckId id() {
        return CheckId.CREDENTIAL_TYPE_AUTHORIZED;
    }

    @Override
    public CheckResult run(VerificationContext ctx) {
        var meta = RegistryChecks.metadata(ctx);
        if (meta.isEmpty()) return RegistryChecks.unmet(ctx, id());
        List<String> types = ctx.credential.credentialTypes().stream().filter(t -> !"VerifiableCredential".equals(t)).toList();
        if (types.isEmpty()) return CheckResult.fail(id(), "NO_CREDENTIAL_TYPE", "The credential does not declare a specific type to authorise.");
        var authorized = meta.get().authorizedCredentialTypes();
        if (authorized.contains(WILDCARD) || authorized.containsAll(types)) {
            return CheckResult.pass(id(), "CREDENTIAL_TYPE_AUTHORIZED", "The issuer is authorised to issue this type of credential.");
        }
        return CheckResult.fail(id(), "CREDENTIAL_TYPE_NOT_AUTHORIZED", "The issuer is not authorised to issue this type of credential.");
    }
}
