package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.TestFixtures.FakeFetcher;
import io.inji.verify.issuer.did.*;
import io.inji.verify.issuer.metadata.IssuerMetadataService;
import io.inji.verify.issuer.metadata.TtlCache;
import io.inji.verify.issuer.model.*;
import io.inji.verify.issuer.net.FetchResult;
import io.inji.verify.issuer.policy.TrustPolicy;
import io.inji.verify.issuer.policy.TrustPolicyEngine;
import io.inji.verify.issuer.registry.*;
import io.inji.verify.issuer.registry.TrqpTestSupport.StubFetcher;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.util.List;

import static io.inji.verify.issuer.TestFixtures.*;
import static io.inji.verify.issuer.registry.TrqpTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real engine, resolver, checks and policies on top of the TRQP adapter with a stubbed registry transport. */
class TrqpEngineIntegrationTest {

    static final String DID_URL = "https://issuer.example.org/.well-known/did.json";
    private final KeyPair key = ed25519();

    private IssuerVerificationResult run(TrustPolicy policy, StubFetcher registryHttp) {
        FakeFetcher did = new FakeFetcher().json(DID_URL, didDocument(ISSUER, KEY_ID, key.getPublic(), ISSUER, true, true));
        DidResolvers resolvers = new DidResolvers(List.of(new DidWebResolver(did, new DidDocumentParser()), new DidJwkResolver()));
        var registry = new TrqpIssuerTrustRegistry("trqp-registry", "https://registry.example.org", AUTHORITY, "issue", registryHttp);
        IssuerMetadataService meta = new IssuerMetadataService(List.of(registry), new TtlCache<>(10, CLOCK),
                Duration.ofMinutes(5), Duration.ofMinutes(1), Duration.ZERO, CLOCK);
        return new IssuerVerificationEngine(resolvers, meta, new TrustPolicyEngine(), policy, CLOCK, Duration.ofSeconds(60))
                .verify(ldp(ISSUER, KEY_ID));
    }

    @Test
    void authorizedIssuerIsTrustedUnderPolicyD() {
        StubFetcher http = new StubFetcher();
        http.byResource = r -> ok(answer(r, true));
        var r = run(TrustPolicy.authorizationOnly(), http);
        assertEquals(TrustStatus.TRUSTED, r.overallStatus());
        assertEquals(Authenticity.VERIFIED, r.cryptographicAuthenticity());
        assertEquals(OrganizationalTrust.TRUSTED, r.organizationalTrust());
        assertNull(r.issuerName(), "no name is invented for TRQP-only data");
        assertEquals("trqp-registry", r.trustRegistry().registryId());
        assertEquals(1, http.bodies.size(), "one query for the one specific credential type");
        assertEquals(TYPE, http.bodies.get(0).get("resource").asText());
    }

    @Test
    void deniedIssuerIsUntrustedEvenThoughTheSignatureAndKeyAreFine() {
        StubFetcher http = new StubFetcher();
        http.byResource = r -> ok(answer(r, false));
        var r = run(TrustPolicy.authorizationOnly(), http);
        assertEquals(TrustStatus.UNTRUSTED, r.overallStatus());
        assertEquals(DisplayStatus.ISSUER_NOT_FOUND, r.displayStatus());
        assertEquals(Authenticity.VERIFIED, r.cryptographicAuthenticity(), "the two questions stay independent");
    }

    @Test
    void registryOutageIsInconclusiveNotUntrusted() {
        StubFetcher http = new StubFetcher(); // every POST times out
        var r = run(TrustPolicy.authorizationOnly(), http);
        assertEquals(TrustStatus.INCONCLUSIVE, r.overallStatus());
        assertEquals(DisplayStatus.VERIFICATION_INCONCLUSIVE, r.displayStatus());
    }

    @Test
    void wrongEndpointIsInconclusiveNotAnAccusation() {
        StubFetcher http = new StubFetcher();
        http.byResource = r -> new FetchResult(FetchResult.Outcome.NOT_FOUND, 404, "<html/>".getBytes(), "HTTP_404");
        assertEquals(TrustStatus.INCONCLUSIVE, run(TrustPolicy.authorizationOnly(), http).overallStatus());
    }

    @Test
    void policyAIsNeverSatisfiedByTrqpAloneBecauseAccreditationDataDoesNotExist() {
        StubFetcher http = new StubFetcher();
        http.byResource = r -> ok(answer(r, true));
        assertNotEquals(TrustStatus.TRUSTED, run(TrustPolicy.registryStrict(), http).overallStatus());
    }

    @Test
    void registryIsQueriedOncePerTypeSetAndCachedAcrossRepeats() {
        StubFetcher http = new StubFetcher();
        http.byResource = r -> ok(answer(r, true));
        FakeFetcher did = new FakeFetcher().json(DID_URL, didDocument(ISSUER, KEY_ID, key.getPublic(), ISSUER, true, true));
        DidResolvers resolvers = new DidResolvers(List.of(new DidWebResolver(did, new DidDocumentParser())));
        var registry = new TrqpIssuerTrustRegistry("r", "https://registry.example.org", AUTHORITY, "issue", http);
        IssuerMetadataService meta = new IssuerMetadataService(List.of(registry), new TtlCache<>(10, CLOCK),
                Duration.ofMinutes(5), Duration.ofMinutes(1), Duration.ZERO, CLOCK);
        var engine = new IssuerVerificationEngine(resolvers, meta, new TrustPolicyEngine(), TrustPolicy.authorizationOnly(), CLOCK, Duration.ofSeconds(60));

        engine.verify(ldp(ISSUER, KEY_ID));
        engine.verify(ldp(ISSUER, KEY_ID));
        assertEquals(1, http.bodies.size(), "second verification served from cache");

        engine.verify(new CredentialIssuerContext("ldp_vc", ISSUER, List.of("VerifiableCredential", "AnotherType"), KEY_ID, null, "assertionMethod"));
        assertEquals(2, http.bodies.size(), "a different type set must not reuse the cached authorization");
        assertEquals("AnotherType", http.bodies.get(1).get("resource").asText());
    }

    @Test
    void typeAwareCacheKeyIsOrderIndependentAndStaticRegistriesIgnoreTypes() {
        StubFetcher http = new StubFetcher();
        http.byResource = r -> ok(answer(r, true));
        var trqp = new TrqpIssuerTrustRegistry("r", "https://registry.example.org", AUTHORITY, "issue", http);
        IssuerMetadataService meta = new IssuerMetadataService(List.of(trqp), new TtlCache<>(10, CLOCK),
                Duration.ofMinutes(5), Duration.ofMinutes(1), Duration.ZERO, CLOCK);
        meta.lookup(ISSUER, List.of("A", "B"));
        int afterFirst = http.bodies.size();
        meta.lookup(ISSUER, List.of("B", "A"));
        assertEquals(afterFirst, http.bodies.size());

        int[] calls = {0};
        IssuerTrustRegistry counting = new IssuerTrustRegistry() {
            public String registryId() {
                return "c";
            }

            public RegistryLookup lookup(String issuerId) {
                calls[0]++;
                return new RegistryLookup.NotFound("c");
            }
        };
        IssuerMetadataService plain = new IssuerMetadataService(List.of(counting), new TtlCache<>(10, CLOCK),
                Duration.ofMinutes(5), Duration.ofMinutes(1), Duration.ZERO, CLOCK);
        plain.lookup(ISSUER, List.of("A"));
        plain.lookup(ISSUER, List.of("B"));
        assertEquals(1, calls[0], "registries that ignore types keep the original per-issuer cache key");
        plain.invalidate(ISSUER);
        plain.lookup(ISSUER, List.of("A"));
        assertEquals(2, calls[0]);
    }

    @Test
    void policyDRequiresCryptographicBindingAndAuthorizationOnly() {
        TrustPolicy d = TrustPolicy.authorizationOnly();
        assertEquals("D", d.name());
        assertTrue(d.isRequired(CheckId.SIGNATURE_KEY_AUTHORIZED));
        assertTrue(d.isRequired(CheckId.ISSUER_REGISTERED));
        assertTrue(d.isRequired(CheckId.CREDENTIAL_TYPE_AUTHORIZED));
        assertFalse(d.isRequired(CheckId.ACCREDITATION_VALID));
        assertFalse(d.isRequired(CheckId.TRUST_FRAMEWORK_VALID));
    }
}
