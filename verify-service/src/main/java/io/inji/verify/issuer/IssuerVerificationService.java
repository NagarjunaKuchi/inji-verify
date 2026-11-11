package io.inji.verify.issuer;

import io.inji.verify.issuer.engine.IssuerVerificationEngine;
import io.inji.verify.issuer.extract.CredentialIssuerExtractor;
import io.inji.verify.issuer.extract.IssuerExtractionException;
import io.inji.verify.issuer.model.CredentialIssuerContext;
import io.inji.verify.issuer.model.IssuerVerificationResult;
import io.inji.verify.issuer.model.TrustStatus;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Entry point used by the credential verification flow. Never throws: whatever happens inside issuer
 * verification must not break existing credential verification, and failures are reported as INCONCLUSIVE
 * (never as proof of a malicious issuer).
 */
public class IssuerVerificationService {

    private static final Logger LOG = Logger.getLogger(IssuerVerificationService.class.getName());

    private final CredentialIssuerExtractor extractor;
    private final IssuerVerificationEngine engine;
    private final boolean runByDefault;
    private final boolean enforce;

    public IssuerVerificationService(CredentialIssuerExtractor extractor, IssuerVerificationEngine engine, boolean runByDefault, boolean enforce) {
        this.extractor = extractor;
        this.engine = engine;
        this.runByDefault = runByDefault;
        this.enforce = enforce;
    }

    /** Whether to run for a request: an explicit request flag wins over the server default. */
    public boolean shouldVerify(Boolean requested) {
        return requested != null ? requested : runByDefault;
    }

    /** When true, an issuer that is not TRUSTED makes the overall credential result unsuccessful. */
    public boolean isEnforcing() {
        return enforce;
    }

    public boolean isTrusted(IssuerVerificationResult result) {
        return result != null && result.overallStatus() == TrustStatus.TRUSTED;
    }

    public IssuerVerificationResult verify(String credential) {
        try {
            CredentialIssuerContext ctx = extractor.extract(credential);
            return engine.verify(ctx);
        } catch (IssuerExtractionException e) {
            return e.kind() == IssuerExtractionException.Kind.UNSUPPORTED_FORMAT
                    ? engine.inconclusive(null, "UNSUPPORTED_CREDENTIAL_FORMAT", "Issuer verification is not supported for this credential format.")
                    : engine.inconclusive(null, "MALFORMED_CREDENTIAL", "The credential could not be read for issuer verification.");
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "Issuer verification failed unexpectedly", e);
            return engine.inconclusive(null, "INTERNAL_ERROR", "Issuer verification could not be completed.");
        }
    }
}
