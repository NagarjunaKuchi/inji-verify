package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.did.DidResolution;
import io.inji.verify.issuer.identifier.IssuerIdentifier;
import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;
import io.inji.verify.issuer.model.CredentialIssuerContext;
import io.inji.verify.issuer.policy.TrustPolicy;
import io.inji.verify.issuer.registry.RegistryLookup;

import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;
import java.util.function.Supplier;

/** Per-verification state. DID resolution and registry lookup are performed at most once, lazily. */
public final class VerificationContext {

    public final CredentialIssuerContext credential;
    public final IssuerIdentifier identifier;
    public final TrustPolicy policy;
    public final Instant now;
    public final Duration clockSkew;
    public final boolean registryConfigured;
    public final Map<CheckId, CheckResult> results = new EnumMap<>(CheckId.class);

    /** Id of the DID verification method that PUBLIC_KEY_VALID matched; consumed by SIGNATURE_KEY_AUTHORIZED. */
    public String matchedMethodId;

    private final Supplier<DidResolution> didSupplier;
    private final Supplier<RegistryLookup> registrySupplier;
    private DidResolution did;
    private RegistryLookup registry;

    public VerificationContext(CredentialIssuerContext credential, IssuerIdentifier identifier, TrustPolicy policy, Instant now,
                               Duration clockSkew, boolean registryConfigured,
                               Supplier<DidResolution> didSupplier, Supplier<RegistryLookup> registrySupplier) {
        this.credential = credential;
        this.identifier = identifier;
        this.policy = policy;
        this.now = now;
        this.clockSkew = clockSkew;
        this.registryConfigured = registryConfigured;
        this.didSupplier = didSupplier;
        this.registrySupplier = registrySupplier;
    }

    public DidResolution did() {
        if (did == null) did = didSupplier.get();
        return did;
    }

    public RegistryLookup registry() {
        if (registry == null) registry = registrySupplier.get();
        return registry;
    }

    /** Registry lookup only for well-formed, supported identifiers, so garbage never reaches a registry. */
    public boolean canQueryRegistry() {
        return identifier.isSupported();
    }
}
