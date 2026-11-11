package io.inji.verify.issuer.did;

import io.inji.verify.issuer.TestFixtures.FakeFetcher;
import io.inji.verify.issuer.identifier.IssuerIdentifier;
import io.inji.verify.issuer.metadata.TtlCache;
import io.inji.verify.issuer.net.FetchResult;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

import static io.inji.verify.issuer.TestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class DidTest {

    private final DidDocumentParser parser = new DidDocumentParser();

    // ---- did:web URL mapping ----
    @Test
    void didWebUrlsFollowTheSpec() {
        assertEquals(URI.create("https://example.com/.well-known/did.json"), DidWebUrls.toUri("did:web:example.com"));
        assertEquals(URI.create("https://example.com/user/alice/did.json"), DidWebUrls.toUri("did:web:example.com:user:alice"));
        assertEquals(URI.create("https://example.com:8443/.well-known/did.json"), DidWebUrls.toUri("did:web:example.com%3A8443"));
        assertEquals(URI.create("https://example.com/.well-known/did.json"), DidWebUrls.toUri("did:web:EXAMPLE.com"));
    }

    @Test
    void didWebUrlsRejectTraversalEncodingAndInjection() {
        for (String bad : new String[]{"did:web:example.com:..:admin", "did:web:example.com:a%2Fb", "did:web:example.com:", "did:web:exa mple.com",
                "did:web:example.com%3A99999", "did:web:user@example.com", "did:web:example.com:a:.", "did:web:"}) {
            assertThrows(IllegalArgumentException.class, () -> DidWebUrls.toUri(bad), bad);
        }
    }

    // ---- parser ----
    @Test
    void parsesDocumentAndResolvesRelativeReferences() throws Exception {
        KeyPair kp = ed25519();
        String doc = "{\"id\":\"" + ISSUER + "\",\"verificationMethod\":[{\"id\":\"#key-0\",\"type\":\"JsonWebKey2020\",\"controller\":\"" + ISSUER + "\",\"publicKeyJwk\":" + ed25519Jwk(kp.getPublic()) + "}],"
                + "\"assertionMethod\":[\"#key-0\"],\"authentication\":[{\"id\":\"#key-1\",\"type\":\"JsonWebKey2020\",\"controller\":\"" + ISSUER + "\",\"publicKeyJwk\":" + ed25519Jwk(kp.getPublic()) + "}]}";
        DidDocument d = parser.parse(doc.getBytes(), ISSUER);
        assertTrue(d.methods().containsKey(KEY_ID));
        assertTrue(d.methods().containsKey(ISSUER + "#key-1"));
        assertTrue(d.assertionMethod().contains(KEY_ID));
        assertTrue(d.authentication().contains(ISSUER + "#key-1"));
    }

    private String parseError(String doc) {
        return assertThrows(MalformedDidDocumentException.class, () -> parser.parse(doc.getBytes(), ISSUER)).reasonCode();
    }

    @Test
    void rejectsMaliciousOrInconsistentDocuments() {
        assertEquals("DID_DOCUMENT_NOT_VALID_JSON", parseError("not json"));
        assertEquals("DID_DOCUMENT_NOT_AN_OBJECT", parseError("[]"));
        assertEquals("DID_DOCUMENT_ID_MISMATCH", parseError("{\"id\":\"did:web:evil.example.com\"}"));
        assertEquals("DID_DOCUMENT_NOT_VALID_JSON", parseError("{\"id\":\"" + ISSUER + "\",\"id\":\"" + ISSUER + "\"}"), "duplicate keys");
        assertEquals("VERIFICATION_METHOD_ID_OUT_OF_SCOPE", parseError("{\"id\":\"" + ISSUER + "\",\"verificationMethod\":[{\"id\":\"did:web:evil.example.com#k\",\"type\":\"JsonWebKey2020\",\"controller\":\"" + ISSUER + "\"}]}"));
        assertEquals("DUPLICATE_VERIFICATION_METHOD_ID", parseError("{\"id\":\"" + ISSUER + "\",\"verificationMethod\":[{\"id\":\"#a\",\"type\":\"T\",\"controller\":\"" + ISSUER + "\"},{\"id\":\"#a\",\"type\":\"T\",\"controller\":\"" + ISSUER + "\"}]}"));
        assertEquals("INVALID_VERIFICATION_METHOD", parseError("{\"id\":\"" + ISSUER + "\",\"verificationMethod\":[{\"id\":\"#a\"}]}"));
        assertEquals("INVALID_RELATIONSHIP", parseError("{\"id\":\"" + ISSUER + "\",\"assertionMethod\":\"#a\"}"));
    }

    @Test
    void rejectsOversizedMethodListsAndDeepNesting() {
        StringBuilder many = new StringBuilder("{\"id\":\"" + ISSUER + "\",\"verificationMethod\":[");
        for (int i = 0; i < DidDocumentParser.MAX_METHODS + 1; i++) {
            many.append(i > 0 ? "," : "").append("{\"id\":\"#k").append(i).append("\",\"type\":\"T\",\"controller\":\"").append(ISSUER).append("\"}");
        }
        assertEquals("INVALID_VERIFICATION_METHOD_LIST", parseError(many.append("]}").toString()));
        assertEquals("DID_DOCUMENT_NOT_VALID_JSON", parseError("{\"id\":\"" + ISSUER + "\",\"x\":" + "[".repeat(200) + "]".repeat(200) + "}"));
    }

    // ---- did:web resolver ----
    private static final String URL = "https://issuer.example.org/.well-known/did.json";

    @Test
    void didWebResolvesValidDocument() {
        KeyPair kp = ed25519();
        FakeFetcher f = new FakeFetcher().json(URL, didDocument(ISSUER, KEY_ID, kp.getPublic(), ISSUER, true, true));
        assertTrue(new DidWebResolver(f, parser).resolve(ISSUER) instanceof DidResolution.Resolved);
    }

    @Test
    void didWebMapsFailuresToDistinctOutcomes() {
        DidResolver notFound = new DidWebResolver(new FakeFetcher().result(URL, FetchResult.of(FetchResult.Outcome.NOT_FOUND, "HTTP_404")), parser);
        assertTrue(notFound.resolve(ISSUER) instanceof DidResolution.NotFound);
        DidResolver timeout = new DidWebResolver(new FakeFetcher(), parser);
        assertEquals("DID_RESOLUTION_TIMEOUT", ((DidResolution.Unavailable) timeout.resolve(ISSUER)).reasonCode());
        DidResolver blocked = new DidWebResolver(new FakeFetcher().result(URL, FetchResult.of(FetchResult.Outcome.BLOCKED, "ADDRESS_NOT_PUBLIC")), parser);
        assertTrue(blocked.resolve(ISSUER) instanceof DidResolution.Blocked);
        DidResolver server = new DidWebResolver(new FakeFetcher().result(URL, FetchResult.of(FetchResult.Outcome.HTTP_ERROR, "HTTP_503")), parser);
        assertTrue(server.resolve(ISSUER) instanceof DidResolution.Unavailable);
        DidResolver big = new DidWebResolver(new FakeFetcher().result(URL, FetchResult.of(FetchResult.Outcome.TOO_LARGE, "x")), parser);
        assertTrue(big.resolve(ISSUER) instanceof DidResolution.Malformed);
        DidResolver garbage = new DidWebResolver(new FakeFetcher().json(URL, "<html>"), parser);
        assertTrue(garbage.resolve(ISSUER) instanceof DidResolution.Malformed);
    }

    @Test
    void didWebDoesNotAcceptDocumentForAnotherDid() {
        KeyPair kp = ed25519();
        String other = didDocument("did:web:other.example.org", "did:web:other.example.org#key-0", kp.getPublic(), "did:web:other.example.org", true, true);
        DidResolution r = new DidWebResolver(new FakeFetcher().json(URL, other), parser).resolve(ISSUER);
        assertEquals("DID_DOCUMENT_ID_MISMATCH", ((DidResolution.Malformed) r).reasonCode());
    }

    // ---- did:jwk ----
    @Test
    void didJwkIsSelfContained() {
        KeyPair kp = ed25519();
        String did = "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(ed25519Jwk(kp.getPublic()).getBytes());
        DidResolution.Resolved r = (DidResolution.Resolved) new DidJwkResolver().resolve(did);
        assertTrue(r.document().assertionMethod().contains(did + "#0"));
        assertEquals(did, r.document().methods().get(did + "#0").controller());
    }

    @Test
    void didJwkRejectsPrivateKeysAndGarbage() {
        String priv = "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik\",\"d\":\"AAAA\"}".getBytes());
        assertTrue(new DidJwkResolver().resolve(priv) instanceof DidResolution.Malformed);
        assertTrue(new DidJwkResolver().resolve("did:jwk:%%%") instanceof DidResolution.Malformed);
    }

    // ---- dispatch + cache ----
    @Test
    void dispatchesByTypeAndReportsUnsupported() {
        DidResolvers resolvers = new DidResolvers(List.of(new DidJwkResolver()));
        assertTrue(resolvers.resolve(IssuerIdentifier.parse("did:web:example.com")) instanceof DidResolution.Unsupported);
        assertTrue(resolvers.resolve(IssuerIdentifier.parse("did:ion:abc")) instanceof DidResolution.Unsupported);
    }

    @Test
    void cacheStoresOnlySuccessesAndExpires() {
        KeyPair kp = ed25519();
        FakeFetcher f = new FakeFetcher();
        var clock = new MutableClock();
        CachingDidResolver c = new CachingDidResolver(new DidWebResolver(f, parser), new TtlCache<>(10, clock), Duration.ofMinutes(5));
        assertTrue(c.resolve(ISSUER) instanceof DidResolution.Unavailable);          // failure: not cached
        f.json(URL, didDocument(ISSUER, KEY_ID, kp.getPublic(), ISSUER, true, true));
        assertTrue(c.resolve(ISSUER) instanceof DidResolution.Resolved);             // heals immediately
        int calls = f.requested.size();
        assertTrue(c.resolve(ISSUER) instanceof DidResolution.Resolved);
        assertEquals(calls, f.requested.size(), "second call served from cache");
        clock.advance(Duration.ofMinutes(6));
        c.resolve(ISSUER);
        assertEquals(calls + 1, f.requested.size(), "expired entry refetched");
        c.invalidate(ISSUER);
        c.resolve(ISSUER);
        assertEquals(calls + 2, f.requested.size(), "explicit invalidation refetches");
    }

    static final class MutableClock extends java.time.Clock {
        private java.time.Instant now = NOW;

        void advance(Duration d) {
            now = now.plus(d);
        }

        public java.time.ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
        }

        public java.time.Clock withZone(java.time.ZoneId z) {
            return this;
        }

        public java.time.Instant instant() {
            return now;
        }
    }
}
