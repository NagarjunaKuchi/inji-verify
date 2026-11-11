package io.inji.verify.issuer.registry;

import io.inji.verify.issuer.model.IssuerMetadata;

/** Registry answer. NotFound is evidence; Unavailable is not. */
public sealed interface RegistryLookup {
    record Found(String registryId, IssuerMetadata metadata) implements RegistryLookup {
    }

    record NotFound(String registryId) implements RegistryLookup {
    }

    record Unavailable(String registryId, String reasonCode) implements RegistryLookup {
    }
}
