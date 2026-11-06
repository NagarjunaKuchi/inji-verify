package io.inji.verify.issuer.did;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.issuer.crypto.KeyException;
import io.inji.verify.issuer.crypto.KeyMaterial;
import io.inji.verify.issuer.identifier.IssuerIdentifier;

import java.util.Base64;
import java.util.Map;
import java.util.Set;

/** did:jwk is self-contained: the DID encodes the key, so no network access is needed. */
public final class DidJwkResolver implements DidResolver {

    private final ObjectMapper mapper = new ObjectMapper(JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build());

    @Override
    public IssuerIdentifier.Type supportedType() {
        return IssuerIdentifier.Type.DID_JWK;
    }

    @Override
    public DidResolution resolve(String did) {
        if (did == null || !did.startsWith("did:jwk:") || did.length() > 2048) return new DidResolution.Malformed("INVALID_ISSUER_IDENTIFIER");
        try {
            byte[] json = Base64.getUrlDecoder().decode(did.substring("did:jwk:".length()));
            JsonNode jwk = mapper.readTree(json);
            KeyMaterial.fromJwk(jwk); // rejects private material / unsupported shapes
            String id = did + "#0";
            VerificationMethod vm = new VerificationMethod(id, "JsonWebKey2020", did, jwk, null);
            return new DidResolution.Resolved(new DidDocument(did, Map.of(id, vm), Set.of(id), Set.of(id)));
        } catch (KeyException e) {
            return new DidResolution.Malformed(e.reasonCode());
        } catch (Exception e) {
            return new DidResolution.Malformed("INVALID_DID_JWK");
        }
    }
}
