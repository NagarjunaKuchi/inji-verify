package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.crypto.KeyException;
import io.inji.verify.issuer.crypto.KeyInfo;
import io.inji.verify.issuer.crypto.KeyMaterial;
import io.inji.verify.issuer.did.DidDocument;
import io.inji.verify.issuer.did.DidResolution;
import io.inji.verify.issuer.did.VerificationMethod;
import io.inji.verify.issuer.identifier.IssuerIdentifier;
import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;
import io.inji.verify.issuer.model.IssuerMetadata;
import io.inji.verify.issuer.registry.RegistryLookup;

/**
 * Key ownership and substitution check. For DID issuers the signing key must be a verification method
 * of the issuer's own DID document, controlled by that DID, of an acceptable type, and (when the
 * credential carries a verifiable key identity such as an x5c leaf) identical to it. For https issuers
 * the key must be registered for the issuer in an independent trust registry.
 */
public final class PublicKeyCheck implements IssuerCheck {

    @Override
    public CheckId id() {
        return CheckId.PUBLIC_KEY_VALID;
    }

    @Override
    public CheckResult run(VerificationContext ctx) {
        if (ctx.identifier.type() == IssuerIdentifier.Type.HTTPS_URL) return registryBound(ctx);
        if (!ctx.identifier.isDid()) return CheckResult.notEvaluated(id(), "Not evaluated because the issuer identifier is not usable.");
        if (!(ctx.did() instanceof DidResolution.Resolved resolved)) {
            return CheckResult.notEvaluated(id(), "Not evaluated because a valid issuer DID document is not available.");
        }
        DidDocument doc = resolved.document();
        String issuer = ctx.identifier.value();
        String keyRef = ctx.credential.signingKeyId();
        String credThumb = ctx.credential.signingKeyThumbprint();

        VerificationMethod vm = null;
        if (keyRef != null) {
            if (!keyRef.startsWith(issuer + "#")) {
                return CheckResult.fail(id(), "ISSUER_KEY_MISMATCH", "The signing key does not belong to the issuer identified in the credential.");
            }
            vm = doc.methods().get(keyRef);
            if (vm == null) return CheckResult.fail(id(), "KEY_NOT_IN_DID_DOCUMENT", "The signing key is not published in the issuer's DID document.");
        } else if (credThumb != null) {
            for (VerificationMethod candidate : doc.methods().values()) {
                try {
                    if (credThumb.equals(keyInfo(candidate).thumbprint())) {
                        vm = candidate;
                        break;
                    }
                } catch (KeyException ignored) {
                    // a method we cannot parse cannot match
                }
            }
            if (vm == null) return CheckResult.fail(id(), "KEY_NOT_IN_DID_DOCUMENT", "The signing key is not published in the issuer's DID document.");
        } else {
            return CheckResult.inconclusive(id(), "NO_SIGNING_KEY_REFERENCE", "The credential does not identify which key signed it.");
        }

        if (!issuer.equals(vm.controller())) {
            return CheckResult.fail(id(), "KEY_CONTROLLER_MISMATCH", "The signing key is not controlled by the issuer.");
        }
        KeyInfo key;
        try {
            key = keyInfo(vm);
        } catch (KeyException e) {
            return e.kind() == KeyException.Kind.UNSUPPORTED
                    ? CheckResult.inconclusive(id(), e.reasonCode(), "The issuer's key format is not supported by this verifier.")
                    : CheckResult.fail(id(), "INVALID_PUBLIC_KEY", "The issuer's public key is invalid or not acceptable (" + e.reasonCode() + ").");
        }
        if (credThumb != null && !credThumb.equals(key.thumbprint())) {
            return CheckResult.fail(id(), "KEY_SUBSTITUTION", "The key that signed the credential differs from the key published by the issuer.");
        }
        ctx.matchedMethodId = vm.id();
        return CheckResult.pass(id(), "KEY_BOUND_TO_ISSUER", "The signing key is published by, and controlled by, the issuer.");
    }

    private CheckResult registryBound(VerificationContext ctx) {
        if (!ctx.registryConfigured) {
            return CheckResult.inconclusive(id(), "NO_INDEPENDENT_KEY_SOURCE", "The issuer's keys cannot be confirmed without a trust registry.");
        }
        var r = ctx.registry();
        if (r instanceof RegistryLookup.Unavailable u) {
            return CheckResult.inconclusive(id(), u.reasonCode(), "The trust registry could not be consulted. This does not indicate a problem with the issuer.");
        }
        if (!(r instanceof RegistryLookup.Found f)) {
            return CheckResult.inconclusive(id(), "NO_INDEPENDENT_KEY_SOURCE", "The issuer's keys cannot be confirmed because the issuer is not listed.");
        }
        IssuerMetadata m = f.metadata();
        String credThumb = ctx.credential.signingKeyThumbprint();
        if (m.keyThumbprints().isEmpty()) return CheckResult.inconclusive(id(), "NO_INDEPENDENT_KEY_SOURCE", "The registry lists no keys for this issuer.");
        if (credThumb == null) return CheckResult.inconclusive(id(), "NO_SIGNING_KEY_REFERENCE", "The credential does not carry a verifiable key identity.");
        return m.keyThumbprints().contains(credThumb)
                ? CheckResult.pass(id(), "KEY_REGISTERED_FOR_ISSUER", "The signing key is registered for the issuer.")
                : CheckResult.fail(id(), "KEY_SUBSTITUTION", "The key that signed the credential is not registered for this issuer.");
    }

    static KeyInfo keyInfo(VerificationMethod vm) throws KeyException {
        if (vm.publicKeyJwk() != null) return KeyMaterial.fromJwk(vm.publicKeyJwk());
        if (vm.publicKeyMultibase() != null) return KeyMaterial.fromMultibase(vm.publicKeyMultibase());
        throw new KeyException(KeyException.Kind.UNSUPPORTED, "UNSUPPORTED_KEY_ENCODING");
    }
}
