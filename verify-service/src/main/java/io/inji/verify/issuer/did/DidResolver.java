package io.inji.verify.issuer.did;

import io.inji.verify.issuer.identifier.IssuerIdentifier;

public interface DidResolver {
    IssuerIdentifier.Type supportedType();

    /** Never throws; every failure is a {@link DidResolution} variant. */
    DidResolution resolve(String did);
}
