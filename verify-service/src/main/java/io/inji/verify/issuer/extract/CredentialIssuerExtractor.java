package io.inji.verify.issuer.extract;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.issuer.crypto.KeyException;
import io.inji.verify.issuer.crypto.KeyMaterial;
import io.inji.verify.issuer.model.CredentialIssuerContext;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Extracts ONLY the issuer identifier, credential type(s) and signing-key reference from a credential.
 * Names, logos, organisation details etc. embedded in the credential are never read: they are
 * attacker-controlled. Supported: JSON-LD (ldp_vc) and JWT/SD-JWT based credentials. CWT is reported
 * as unsupported (inconclusive), not as an error.
 */
public final class CredentialIssuerExtractor {

    private static final int MAX_CREDENTIAL_CHARS = 2_000_000;

    private final ObjectMapper mapper = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(64).build())
            .build());

    public CredentialIssuerContext extract(String credential) throws IssuerExtractionException {
        if (credential == null || credential.isBlank() || credential.length() > MAX_CREDENTIAL_CHARS) {
            throw new IssuerExtractionException(IssuerExtractionException.Kind.MALFORMED, "empty or oversized credential");
        }
        String c = credential.trim();
        if (c.startsWith("{")) return fromLdp(c);
        String jwt = c.split("~", -1)[0];
        if (jwt.split("\\.", -1).length == 3) return fromJwt(jwt);
        throw new IssuerExtractionException(IssuerExtractionException.Kind.UNSUPPORTED_FORMAT, "unsupported credential format");
    }

    private CredentialIssuerContext fromLdp(String json) throws IssuerExtractionException {
        JsonNode root = readJson(json.getBytes(StandardCharsets.UTF_8));
        String issuer = null;
        JsonNode i = root.get("issuer");
        if (i != null && i.isTextual()) issuer = i.asText();
        else if (i != null && i.isObject() && i.path("id").isTextual()) issuer = i.get("id").asText();

        JsonNode proof = root.get("proof");
        if (proof != null && proof.isArray()) proof = proof.size() > 0 ? proof.get(0) : null;
        String vm = null, purpose = null;
        if (proof != null && proof.isObject()) {
            JsonNode v = proof.get("verificationMethod");
            if (v != null && v.isTextual()) vm = v.asText();
            else if (v != null && v.isObject() && v.path("id").isTextual()) vm = v.get("id").asText();
            if (proof.path("proofPurpose").isTextual()) purpose = proof.get("proofPurpose").asText();
        }
        return new CredentialIssuerContext("ldp_vc", issuer, types(root.get("type")), vm, null, purpose);
    }

    private CredentialIssuerContext fromJwt(String jwt) throws IssuerExtractionException {
        String[] parts = jwt.split("\\.", -1);
        JsonNode header = readJson(decode(parts[0]));
        JsonNode payload = readJson(decode(parts[1]));
        String issuer = payload.path("iss").isTextual() ? payload.get("iss").asText() : null;
        List<String> types = new ArrayList<>();
        if (payload.path("vct").isTextual()) types.add(payload.get("vct").asText());
        types.addAll(types(payload.path("vc").get("type")));
        String kid = header.path("kid").isTextual() ? header.get("kid").asText() : null;
        return new CredentialIssuerContext("jwt_vc", issuer, types, kid, leafThumbprint(header), null);
    }

    /** Identity of the key in the x5c leaf certificate, which is the key the SD-JWT verifier actually uses. */
    private String leafThumbprint(JsonNode header) {
        JsonNode x5c = header.get("x5c");
        if (x5c == null || !x5c.isArray() || x5c.size() == 0 || !x5c.get(0).isTextual()) return null;
        try {
            byte[] der = Base64.getDecoder().decode(x5c.get(0).asText());
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
            return KeyMaterial.fromPublicKey(cert.getPublicKey()).thumbprint();
        } catch (KeyException | java.security.GeneralSecurityException | IllegalArgumentException e) {
            return null;
        }
    }

    private static List<String> types(JsonNode t) {
        List<String> out = new ArrayList<>();
        if (t == null) return out;
        if (t.isTextual()) out.add(t.asText());
        else if (t.isArray()) t.forEach(x -> {
            if (x.isTextual()) out.add(x.asText());
        });
        return out;
    }

    private JsonNode readJson(byte[] bytes) throws IssuerExtractionException {
        try {
            JsonNode n = mapper.readTree(bytes);
            if (n == null || !n.isObject()) throw new IssuerExtractionException(IssuerExtractionException.Kind.MALFORMED, "not an object");
            return n;
        } catch (IssuerExtractionException e) {
            throw e;
        } catch (Exception e) {
            throw new IssuerExtractionException(IssuerExtractionException.Kind.MALFORMED, "invalid json");
        }
    }

    private static byte[] decode(String b64url) throws IssuerExtractionException {
        try {
            return Base64.getUrlDecoder().decode(b64url);
        } catch (IllegalArgumentException e) {
            throw new IssuerExtractionException(IssuerExtractionException.Kind.MALFORMED, "invalid base64url");
        }
    }
}
