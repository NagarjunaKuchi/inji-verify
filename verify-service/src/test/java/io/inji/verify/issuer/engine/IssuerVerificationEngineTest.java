package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.TestFixtures.FakeFetcher;
import io.inji.verify.issuer.crypto.KeyMaterial;
import io.inji.verify.issuer.did.*;
import io.inji.verify.issuer.metadata.IssuerMetadataService;
import io.inji.verify.issuer.metadata.TtlCache;
import io.inji.verify.issuer.model.*;
import io.inji.verify.issuer.net.FetchResult;
import io.inji.verify.issuer.policy.TrustPolicy;
import io.inji.verify.issuer.policy.TrustPolicyEngine;
import io.inji.verify.issuer.registry.IssuerTrustRegistry;
import io.inji.verify.issuer.registry.RegistryLookup;
import io.inji.verify.issuer.registry.StaticIssuerTrustRegistry;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static io.inji.verify.issuer.TestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

/** End-to-end issuer verification scenarios using the real resolver, parser, checks and policy engine with fake network and registry. */
class IssuerVerificationEngineTest {

    static final String DID_URL = "https://issuer.example.org/.well-known/did.json";

    private final KeyPair key = ed25519();

    private FakeFetcher goodDidFetcher() {
        return new FakeFetcher().json(DID_URL, didDocument(ISSUER, KEY_ID, key.getPublic(), ISSUER, true, true));
    }

    private IssuerVerificationEngine engine(TrustPolicy policy, FakeFetcher did, IssuerTrustRegistry... registries) {
        DidResolvers resolvers = new DidResolvers(List.of(new DidWebResolver(did, new DidDocumentParser()), new DidJwkResolver()));
        IssuerMetadataService meta = new IssuerMetadataService(List.of(registries), new TtlCache<>(10, CLOCK),
                Duration.ofMinutes(5), Duration.ofMinutes(1), Duration.ZERO, CLOCK);
        return new IssuerVerificationEngine(resolvers, meta, new TrustPolicyEngine(), policy, CLOCK, Duration.ofSeconds(60));
    }

    private IssuerTrustRegistry registryOf(IssuerMetadata... m) {
        return new StaticIssuerTrustRegistry("example-registry", List.of(m));
    }

    private CheckResult check(IssuerVerificationResult r, CheckId id) {
        return r.checks().stream().filter(c -> c.id() == id).findFirst().orElseThrow();
    }

    private IssuerVerificationResult verifyLdp(TrustPolicy p, FakeFetcher did, IssuerTrustRegistry... regs) {
        return engine(p, did, regs).verify(ldp(ISSUER, KEY_ID));
    }

    // ---- happy path & the two independent questions ----
    @Test
    void trustedIssuerUnderStrictRegistryPolicy() {
        var r = verifyLdp(TrustPolicy.registryStrict(), goodDidFetcher(), registryOf(metadata(ISSUER, LifecycleStatus.ACTIVE)));
        assertEquals(TrustStatus.TRUSTED, r.overallStatus());
        assertEquals(DisplayStatus.TRUSTED_ISSUER, r.displayStatus());
        assertEquals(Authenticity.VERIFIED, r.cryptographicAuthenticity());
        assertEquals(OrganizationalTrust.TRUSTED, r.organizationalTrust());
        assertEquals("Example Government Authority", r.issuerName());
        assertEquals("example-registry", r.trustRegistry().registryId());
        assertEquals("VERIFIED", r.trustRegistry().status());
        assertEquals("ACTIVE", r.accreditation().status());
        assertEquals(NOW, r.verifiedAt());
        assertTrue(r.failureReasons().isEmpty());
        assertEquals((long) CheckId.values().length - 1, r.checks().stream().filter(c -> c.status() == CheckStatus.PASS).count(), "all but the not-applicable framework check pass");
    }

    @Test
    void validSignatureAloneNeverMakesAnIssuerTrusted() {
        // cryptographically perfect, but nobody independent vouches for the issuer
        var r = verifyLdp(TrustPolicy.registryStrict(), goodDidFetcher());
        assertEquals(Authenticity.VERIFIED, r.cryptographicAuthenticity());
        assertNotEquals(TrustStatus.TRUSTED, r.overallStatus());
        assertEquals(TrustStatus.INCONCLUSIVE, r.overallStatus());
        assertEquals(OrganizationalTrust.NOT_EVALUATED, r.organizationalTrust());
        assertEquals("NOT_CONFIGURED", r.trustRegistry().status());
    }

    @Test
    void issuerNameComesFromRegistryNeverFromTheCredential() {
        var cred = new CredentialIssuerContext("ldp_vc", ISSUER, List.of(TYPE), KEY_ID, null, "assertionMethod");
        var r = engine(TrustPolicy.registryStrict(), goodDidFetcher(), registryOf(metadata(ISSUER, LifecycleStatus.ACTIVE))).verify(cred);
        assertEquals("Example Government Authority", r.issuerName());
        var unknown = engine(TrustPolicy.cryptographicOnly(), goodDidFetcher()).verify(cred);
        assertNull(unknown.issuerName(), "without a registry no name is shown, even if the credential carried one");
    }

    // ---- policies ----
    @Test
    void policyBDidOnlyIsTrustedButReportsOrganizationalTrustNotEvaluated() {
        var r = verifyLdp(TrustPolicy.cryptographicOnly(), goodDidFetcher());
        assertEquals(TrustStatus.TRUSTED, r.overallStatus());
        assertEquals(Authenticity.VERIFIED, r.cryptographicAuthenticity());
        assertEquals(OrganizationalTrust.NOT_EVALUATED, r.organizationalTrust());
    }

    @Test
    void policyBStillRejectsRevokedIssuer() {
        var r = verifyLdp(TrustPolicy.cryptographicOnly(), goodDidFetcher(), registryOf(metadata(ISSUER, LifecycleStatus.REVOKED)));
        assertEquals(TrustStatus.UNTRUSTED, r.overallStatus());
        assertEquals(DisplayStatus.ISSUER_REVOKED, r.displayStatus());
        assertEquals(Authenticity.VERIFIED, r.cryptographicAuthenticity(), "authentic but no longer trusted");
    }

    @Test
    void policyBToleratesUnlistedIssuerButReportsIt() {
        var r = verifyLdp(TrustPolicy.cryptographicOnly(), goodDidFetcher(), registryOf());
        assertEquals(TrustStatus.TRUSTED, r.overallStatus());
        assertEquals(OrganizationalTrust.UNTRUSTED, r.organizationalTrust());
        assertEquals("NOT_FOUND", r.trustRegistry().status());
    }

    @Test
    void policyCRequiresApprovedFrameworkAndAccreditation() {
        var ok = verifyLdp(TrustPolicy.trustFramework(Set.of("example-trust-framework")), goodDidFetcher(), registryOf(metadata(ISSUER, LifecycleStatus.ACTIVE)));
        assertEquals(TrustStatus.TRUSTED, ok.overallStatus());
        var wrong = verifyLdp(TrustPolicy.trustFramework(Set.of("other")), goodDidFetcher(), registryOf(metadata(ISSUER, LifecycleStatus.ACTIVE)));
        assertEquals(TrustStatus.UNTRUSTED, wrong.overallStatus());
        assertTrue(wrong.failureReasons().contains("TRUST_FRAMEWORK_NOT_APPROVED"));
        var misconfigured = verifyLdp(TrustPolicy.trustFramework(Set.of()), goodDidFetcher(), registryOf(metadata(ISSUER, LifecycleStatus.ACTIVE)));
        assertEquals(TrustStatus.INCONCLUSIVE, misconfigured.overallStatus(), "fail closed on misconfiguration");
    }

    // ---- registry outcomes ----
    @Test
    void suspendedRevokedAndUnknownIssuers() {
        var s = verifyLdp(TrustPolicy.registryStrict(), goodDidFetcher(), registryOf(metadata(ISSUER, LifecycleStatus.SUSPENDED)));
        assertEquals(DisplayStatus.ISSUER_SUSPENDED, s.displayStatus());
        assertEquals(TrustStatus.UNTRUSTED, s.overallStatus());
        var v = verifyLdp(TrustPolicy.registryStrict(), goodDidFetcher(), registryOf(metadata(ISSUER, LifecycleStatus.REVOKED)));
        assertEquals(DisplayStatus.ISSUER_REVOKED, v.displayStatus());
        var n = verifyLdp(TrustPolicy.registryStrict(), goodDidFetcher(), registryOf());
        assertEquals(DisplayStatus.ISSUER_NOT_FOUND, n.displayStatus());
        assertEquals(TrustStatus.UNTRUSTED, n.overallStatus());
    }

    @Test
    void expiredAccreditationAndUnauthorizedTypeMakeIssuerUntrusted() {
        IssuerMetadata base = metadata(ISSUER, LifecycleStatus.ACTIVE);
        var expiredAcc = new IssuerMetadata(ISSUER, "n", "l", "o", "IN", LifecycleStatus.ACTIVE, null, null,
                List.of(new Accreditation("a", "x", LifecycleStatus.ACTIVE, NOW.minusSeconds(1000000), NOW.minusSeconds(86400))), base.trustFrameworks(), base.authorizedCredentialTypes(), Set.of(), null);
        var r = verifyLdp(TrustPolicy.registryStrict(), goodDidFetcher(), registryOf(expiredAcc));
        assertEquals(TrustStatus.UNTRUSTED, r.overallStatus());
        assertTrue(r.failureReasons().contains("ACCREDITATION_EXPIRED"));
        assertEquals("EXPIRED", r.accreditation().status());

        var wrongType = new IssuerMetadata(ISSUER, "n", "l", "o", "IN", LifecycleStatus.ACTIVE, null, null, base.accreditations(), base.trustFrameworks(), Set.of("SomethingElse"), Set.of(), null);
        var r2 = verifyLdp(TrustPolicy.registryStrict(), goodDidFetcher(), registryOf(wrongType));
        assertEquals(TrustStatus.UNTRUSTED, r2.overallStatus());
        assertTrue(r2.failureReasons().contains("CREDENTIAL_TYPE_NOT_AUTHORIZED"));
    }

    @Test
    void registryOutageIsInconclusiveNeverUntrusted() {
        IssuerTrustRegistry down = new IssuerTrustRegistry() {
            public String registryId() {
                return "down";
            }

            public RegistryLookup lookup(String id) {
                return new RegistryLookup.Unavailable("down", "REGISTRY_TIMEOUT");
            }
        };
        var r = verifyLdp(TrustPolicy.registryStrict(), goodDidFetcher(), down);
        assertEquals(TrustStatus.INCONCLUSIVE, r.overallStatus());
        assertEquals(DisplayStatus.VERIFICATION_INCONCLUSIVE, r.displayStatus());
        assertEquals(Authenticity.VERIFIED, r.cryptographicAuthenticity(), "cryptographic result is unaffected by registry outage");
        assertEquals(OrganizationalTrust.INCONCLUSIVE, r.organizationalTrust());
        assertEquals("UNAVAILABLE", r.trustRegistry().status());
        assertTrue(r.failureReasons().contains("REGISTRY_TIMEOUT"));
    }

    // ---- DID resolution outcomes ----
    @Test
    void didTimeoutIsInconclusiveAndDid404IsNotFound() {
        var timeout = verifyLdp(TrustPolicy.registryStrict(), new FakeFetcher(), registryOf(metadata(ISSUER, LifecycleStatus.ACTIVE)));
        assertEquals(TrustStatus.INCONCLUSIVE, timeout.overallStatus());
        assertEquals(Authenticity.INCONCLUSIVE, timeout.cryptographicAuthenticity());

        var gone = verifyLdp(TrustPolicy.registryStrict(), new FakeFetcher().result(DID_URL, FetchResult.of(FetchResult.Outcome.NOT_FOUND, "HTTP_404")), registryOf(metadata(ISSUER, LifecycleStatus.ACTIVE)));
        assertEquals(TrustStatus.UNTRUSTED, gone.overallStatus());
        assertEquals(Authenticity.FAILED, gone.cryptographicAuthenticity());
        assertEquals(DisplayStatus.ISSUER_NOT_FOUND, gone.displayStatus());
    }

    @Test
    void ssrfBlockedDidEndpointIsUntrustedWithoutLeakingDetails() {
        var r = verifyLdp(TrustPolicy.cryptographicOnly(), new FakeFetcher().result(DID_URL, FetchResult.of(FetchResult.Outcome.BLOCKED, "ADDRESS_NOT_PUBLIC")));
        assertEquals(TrustStatus.UNTRUSTED, r.overallStatus());
        String json = r.checks().toString();
        assertFalse(json.contains("ADDRESS_NOT_PUBLIC") || json.contains("10.") || json.contains("169.254"));
    }

    @Test
    void maliciousDidDocumentsAreRejected() {
        String foreign = didDocument("did:web:evil.example.com", "did:web:evil.example.com#key-0", key.getPublic(), "did:web:evil.example.com", true, true);
        var r = verifyLdp(TrustPolicy.cryptographicOnly(), new FakeFetcher().json(DID_URL, foreign));
        assertEquals(TrustStatus.UNTRUSTED, r.overallStatus());
        assertEquals(CheckStatus.FAIL, check(r, CheckId.DID_DOCUMENT_VALID).status());

        String withPrivateKey = "{\"id\":\"" + ISSUER + "\",\"verificationMethod\":[{\"id\":\"#key-0\",\"type\":\"JsonWebKey2020\",\"controller\":\"" + ISSUER
                + "\",\"publicKeyJwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + ed25519X(key.getPublic()) + "\",\"d\":\"AAAA\"}}],\"assertionMethod\":[\"#key-0\"]}";
        var r2 = verifyLdp(TrustPolicy.cryptographicOnly(), new FakeFetcher().json(DID_URL, withPrivateKey));
        assertEquals(TrustStatus.UNTRUSTED, r2.overallStatus());
        assertEquals("INVALID_PUBLIC_KEY", check(r2, CheckId.PUBLIC_KEY_VALID).reasonCode());
    }

    // ---- key relationships ----
    @Test
    void keyMustBeAssertionMethodNotJustAuthentication() {
        var fetcher = new FakeFetcher().json(DID_URL, didDocument(ISSUER, KEY_ID, key.getPublic(), ISSUER, false, true));
        var r = verifyLdp(TrustPolicy.cryptographicOnly(), fetcher);
        assertEquals(TrustStatus.UNTRUSTED, r.overallStatus());
        assertEquals("KEY_NOT_AUTHORIZED_FOR_ASSERTION", check(r, CheckId.SIGNATURE_KEY_AUTHORIZED).reasonCode());
        assertEquals(Authenticity.FAILED, r.cryptographicAuthenticity());
    }

    @Test
    void keyFromAnotherIssuerIsRejectedEvenIfThatDidIsReal() {
        var r = engine(TrustPolicy.cryptographicOnly(), goodDidFetcher()).verify(ldp(ISSUER, "did:web:other.example.org#key-0"));
        assertEquals("ISSUER_KEY_MISMATCH", check(r, CheckId.PUBLIC_KEY_VALID).reasonCode());
        assertEquals(TrustStatus.UNTRUSTED, r.overallStatus());
    }

    @Test
    void keySubstitutionIsDetectedWhenSigningKeyDiffersFromPublishedKey() throws Exception {
        String attackerThumb = KeyMaterial.fromPublicKey(ed25519().getPublic()).thumbprint();
        var cred = new CredentialIssuerContext("jwt_vc", ISSUER, List.of(TYPE), null, attackerThumb, null);
        var r = engine(TrustPolicy.cryptographicOnly(), goodDidFetcher()).verify(cred);
        assertEquals(TrustStatus.UNTRUSTED, r.overallStatus());
        assertEquals("KEY_NOT_IN_DID_DOCUMENT", check(r, CheckId.PUBLIC_KEY_VALID).reasonCode());

        String legit = KeyMaterial.fromPublicKey(key.getPublic()).thumbprint();
        var ok = engine(TrustPolicy.cryptographicOnly(), goodDidFetcher()).verify(new CredentialIssuerContext("jwt_vc", ISSUER, List.of(TYPE), KEY_ID, legit, null));
        assertEquals(TrustStatus.TRUSTED, ok.overallStatus());
        var kidButWrongKey = engine(TrustPolicy.cryptographicOnly(), goodDidFetcher()).verify(new CredentialIssuerContext("jwt_vc", ISSUER, List.of(TYPE), KEY_ID, attackerThumb, null));
        assertEquals("KEY_SUBSTITUTION", check(kidButWrongKey, CheckId.PUBLIC_KEY_VALID).reasonCode());
    }

    // ---- other identifier kinds ----
    @Test
    void didJwkIssuerWorksWithoutNetworkAccess() {
        String did = "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(ed25519Jwk(key.getPublic()).getBytes());
        FakeFetcher none = new FakeFetcher();
        var r = engine(TrustPolicy.cryptographicOnly(), none).verify(new CredentialIssuerContext("ldp_vc", did, List.of(TYPE), did + "#0", null, "assertionMethod"));
        assertEquals(TrustStatus.TRUSTED, r.overallStatus());
        assertTrue(none.requested.isEmpty());
    }

    @Test
    void httpsIssuerIsTrustedOnlyViaRegistryRegisteredKey() throws Exception {
        String thumb = KeyMaterial.fromPublicKey(key.getPublic()).thumbprint();
        String issuer = "https://issuer.example.org";
        IssuerMetadata m = new IssuerMetadata(issuer, "HTTPS Issuer", null, null, "IN", LifecycleStatus.ACTIVE, null, null,
                metadata(ISSUER, LifecycleStatus.ACTIVE).accreditations(), Set.of(), Set.of(TYPE), Set.of(thumb), null);
        var cred = new CredentialIssuerContext("jwt_vc", issuer, List.of(TYPE), null, thumb, null);
        var ok = engine(TrustPolicy.registryStrict(), new FakeFetcher(), registryOf(m)).verify(cred);
        assertEquals(TrustStatus.TRUSTED, ok.overallStatus());
        assertEquals(CheckStatus.NOT_APPLICABLE, check(ok, CheckId.DID_RESOLUTION).status());

        var attacker = new CredentialIssuerContext("jwt_vc", issuer, List.of(TYPE), null, KeyMaterial.fromPublicKey(ed25519().getPublic()).thumbprint(), null);
        assertEquals(TrustStatus.UNTRUSTED, engine(TrustPolicy.registryStrict(), new FakeFetcher(), registryOf(m)).verify(attacker).overallStatus());
        assertEquals(TrustStatus.INCONCLUSIVE, engine(TrustPolicy.cryptographicOnly(), new FakeFetcher()).verify(cred).overallStatus(),
                "an https issuer with no independent key source cannot be cryptographically bound");
    }

    @Test
    void invalidAndUnsupportedIdentifiers() {
        var invalid = engine(TrustPolicy.cryptographicOnly(), new FakeFetcher()).verify(ldp("http://insecure.example.org", null));
        assertEquals(TrustStatus.UNTRUSTED, invalid.overallStatus());
        var missing = engine(TrustPolicy.cryptographicOnly(), new FakeFetcher()).verify(ldp(null, null));
        assertEquals(TrustStatus.UNTRUSTED, missing.overallStatus());
        var unsupported = engine(TrustPolicy.cryptographicOnly(), new FakeFetcher()).verify(ldp("did:ion:EiClkZMDxPKqC9c", "did:ion:EiClkZMDxPKqC9c#k"));
        assertEquals(TrustStatus.INCONCLUSIVE, unsupported.overallStatus(), "unsupported is a limitation of this verifier, not evidence against the issuer");
    }

    // ---- robustness ----
    @Test
    void aCrashingCheckBecomesInconclusiveNotAnException() {
        IssuerCheck boom = new IssuerCheck() {
            public CheckId id() {
                return CheckId.ISSUER_REGISTERED;
            }

            public CheckResult run(VerificationContext ctx) {
                throw new IllegalStateException("secret internals");
            }
        };
        DidResolvers resolvers = new DidResolvers(List.of(new DidWebResolver(goodDidFetcher(), new DidDocumentParser())));
        IssuerMetadataService meta = new IssuerMetadataService(List.of(), new TtlCache<>(1, CLOCK), Duration.ofMinutes(1), Duration.ofMinutes(1), Duration.ZERO, CLOCK);
        var e = new IssuerVerificationEngine(resolvers, meta, new TrustPolicyEngine(), TrustPolicy.registryStrict(), List.of(boom), CLOCK, Duration.ZERO);
        var r = e.verify(ldp(ISSUER, KEY_ID));
        assertEquals("INTERNAL_ERROR", check(r, CheckId.ISSUER_REGISTERED).reasonCode());
        assertFalse(check(r, CheckId.ISSUER_REGISTERED).message().contains("secret"));
        assertNotEquals(TrustStatus.TRUSTED, r.overallStatus());
    }

    @Test
    void registryIsQueriedOncePerVerificationAndDidFetchedOnce() {
        FakeFetcher f = goodDidFetcher();
        int[] lookups = {0};
        IssuerTrustRegistry counting = new IssuerTrustRegistry() {
            public String registryId() {
                return "c";
            }

            public RegistryLookup lookup(String id) {
                lookups[0]++;
                return new RegistryLookup.Found("c", metadata(ISSUER, LifecycleStatus.ACTIVE));
            }
        };
        engine(TrustPolicy.registryStrict(), f, counting).verify(ldp(ISSUER, KEY_ID));
        assertEquals(1, lookups[0]);
        assertEquals(1, f.requested.size());
    }

    @Test
    void garbageIdentifierNeverReachesRegistryOrNetwork() {
        FakeFetcher f = new FakeFetcher();
        int[] lookups = {0};
        IssuerTrustRegistry spy = new IssuerTrustRegistry() {
            public String registryId() {
                return "s";
            }

            public RegistryLookup lookup(String id) {
                lookups[0]++;
                return new RegistryLookup.NotFound("s");
            }
        };
        engine(TrustPolicy.registryStrict(), f, spy).verify(ldp("../../etc/passwd", null));
        assertEquals(0, lookups[0]);
        assertTrue(f.requested.isEmpty());
    }
}
