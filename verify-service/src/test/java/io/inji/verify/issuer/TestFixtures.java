package io.inji.verify.issuer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.issuer.model.Accreditation;
import io.inji.verify.issuer.model.CredentialIssuerContext;
import io.inji.verify.issuer.model.IssuerMetadata;
import io.inji.verify.issuer.model.LifecycleStatus;
import io.inji.verify.issuer.net.FetchResult;
import io.inji.verify.issuer.net.HttpFetcher;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Shared builders for issuer verification tests. Key coordinates are derived from the encoded key, independent of production code. */
public final class TestFixtures {

    public static final Instant NOW = Instant.parse("2026-11-06T10:00:00Z");
    public static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    public static final String ISSUER = "did:web:issuer.example.org";
    public static final String KEY_ID = ISSUER + "#key-0";
    public static final String TYPE = "NationalIdCredential";
    public static final ObjectMapper MAPPER = new ObjectMapper();

    private TestFixtures() {
    }

    public static KeyPair ed25519() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String ed25519X(PublicKey k) {
        byte[] enc = k.getEncoded();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(enc, enc.length - 32, enc.length));
    }

    public static String ed25519Jwk(PublicKey k) {
        return "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + ed25519X(k) + "\"}";
    }

    /** DID document for ISSUER with one Ed25519 key, listed in the given relationships. */
    public static String didDocument(String did, String keyId, PublicKey key, String controller, boolean assertion, boolean authentication) {
        String ref = "\"" + keyId + "\"";
        return "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"id\":\"" + did + "\","
                + "\"verificationMethod\":[{\"id\":\"" + keyId + "\",\"type\":\"JsonWebKey2020\",\"controller\":\"" + controller + "\",\"publicKeyJwk\":" + ed25519Jwk(key) + "}],"
                + "\"assertionMethod\":[" + (assertion ? ref : "") + "],\"authentication\":[" + (authentication ? ref : "") + "]}";
    }


    public static IssuerMetadata metadata(String issuerId, LifecycleStatus status) {
        return new IssuerMetadata(issuerId, "Example Government Authority", "Example Government Authority Ltd", "GOVERNMENT", "IN",
                status, Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2028-01-01T00:00:00Z"),
                List.of(new Accreditation("acc-1", "National Accreditation Board", LifecycleStatus.ACTIVE,
                        Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2028-01-01T00:00:00Z"))),
                Set.of("example-trust-framework"), Set.of(TYPE), Set.of(), null);
    }

    public static CredentialIssuerContext ldp(String issuer, String keyId) {
        return new CredentialIssuerContext("ldp_vc", issuer, List.of("VerifiableCredential", TYPE), keyId, null, "assertionMethod");
    }

    /** Fetcher serving fixed results per URL; anything else is a timeout. */
    public static final class FakeFetcher implements HttpFetcher {
        public final Map<String, FetchResult> responses = new HashMap<>();
        public final java.util.List<String> requested = new java.util.ArrayList<>();

        public FakeFetcher json(String url, String body) {
            responses.put(url, FetchResult.ok(200, body.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            return this;
        }

        public FakeFetcher result(String url, FetchResult r) {
            responses.put(url, r);
            return this;
        }

        @Override
        public FetchResult fetch(URI uri) {
            requested.add(uri.toString());
            return responses.getOrDefault(uri.toString(), FetchResult.of(FetchResult.Outcome.TIMEOUT, "TIMEOUT"));
        }
    }

    public static JsonNode json(String s) {
        try {
            return MAPPER.readTree(s);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
