package io.inji.verify.issuer.did;

import io.inji.verify.issuer.identifier.IssuerIdentifier;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/** Dispatches to the resolver registered for the identifier type. New DID methods are added by registering a resolver. */
public final class DidResolvers {

    private final Map<IssuerIdentifier.Type, DidResolver> byType = new EnumMap<>(IssuerIdentifier.Type.class);

    public DidResolvers(List<DidResolver> resolvers) {
        resolvers.forEach(r -> byType.put(r.supportedType(), r));
    }

    public DidResolution resolve(IssuerIdentifier id) {
        DidResolver r = byType.get(id.type());
        if (r == null) return new DidResolution.Unsupported("UNSUPPORTED_DID_METHOD");
        try {
            return r.resolve(id.value());
        } catch (RuntimeException e) {
            return new DidResolution.Unavailable("DID_RESOLUTION_UNAVAILABLE");
        }
    }
}
