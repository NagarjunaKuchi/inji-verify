package io.inji.verify.issuer.registry;

import java.util.Collection;

/**
 * Vendor-neutral trust registry abstraction. An implementation answers one question: what does this
 * independent source say about the issuer? Registration, lifecycle status, accreditation, framework
 * membership, credential-type permissions and validity are all derived from the returned canonical
 * {@link io.inji.verify.issuer.model.IssuerMetadata} by the verification checks, so a new registry
 * (REST, DID-based trust list, enterprise API) only has to map its own format to that model.
 */
public interface IssuerTrustRegistry {

    String registryId();

    /** Never throws; infrastructure problems are {@link RegistryLookup.Unavailable}. */
    RegistryLookup lookup(String issuerId);

    /**
     * Registries whose answer depends on the credential type being issued (e.g. TRQP authorization queries)
     * override this to return true and implement {@link #lookup(String, Collection)}. All others ignore types.
     */
    default boolean credentialTypeAware() {
        return false;
    }

    /** Never throws. The default ignores the credential types. */
    default RegistryLookup lookup(String issuerId, Collection<String> credentialTypes) {
        return lookup(issuerId);
    }
}
