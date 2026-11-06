package io.inji.verify.issuer.engine;

import io.inji.verify.issuer.did.*;
import io.inji.verify.issuer.identifier.IssuerIdentifier;
import io.inji.verify.issuer.model.*;
import io.inji.verify.issuer.policy.TrustPolicy;
import io.inji.verify.issuer.registry.RegistryLookup;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static io.inji.verify.issuer.TestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for each individual check, driving it with a hand-built context. */
class ChecksTest {

    private final DidDocumentParser parser = new DidDocumentParser();

    private VerificationContext ctx(CredentialIssuerContext cred, TrustPolicy policy, DidResolution did, RegistryLookup registry, boolean registryConfigured) {
        return new VerificationContext(cred, IssuerIdentifier.parse(cred.issuerId()), policy, NOW, Duration.ofSeconds(60), registryConfigured, () -> did, () -> registry);
    }

    private DidResolution doc(KeyPair kp, String controller, boolean assertion, boolean authentication) {
        try {
            return new DidResolution.Resolved(parser.parse(didDocument(ISSUER, KEY_ID, kp.getPublic(), controller, assertion, authentication).getBytes(), ISSUER));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private RegistryLookup found(IssuerMetadata m) {
        return new RegistryLookup.Found("reg", m);
    }

    private CheckStatus status(IssuerCheck c, VerificationContext x) {
        return c.run(x).status();
    }

    private String reason(IssuerCheck c, VerificationContext x) {
        return c.run(x).reasonCode();
    }

    // 1. identifier
    @Test
    void identifierCheck() {
        IssuerCheck c = new IssuerIdentifierCheck();
        assertEquals(CheckStatus.PASS, status(c, ctx(ldp(ISSUER, KEY_ID), TrustPolicy.registryStrict(), null, null, false)));
        assertEquals(CheckStatus.FAIL, status(c, ctx(ldp("not an id", KEY_ID), TrustPolicy.registryStrict(), null, null, false)));
        assertEquals(CheckStatus.FAIL, status(c, ctx(ldp(null, KEY_ID), TrustPolicy.registryStrict(), null, null, false)));
        assertEquals(CheckStatus.FAIL, status(c, ctx(ldp("http://issuer.example.org", KEY_ID), TrustPolicy.registryStrict(), null, null, false)));
        assertEquals(CheckStatus.INCONCLUSIVE, status(c, ctx(ldp("did:ion:abc", KEY_ID), TrustPolicy.registryStrict(), null, null, false)));
        assertEquals(CheckStatus.INCONCLUSIVE, status(c, ctx(ldp("urn:uuid:123", KEY_ID), TrustPolicy.registryStrict(), null, null, false)));
    }

    // 2. DID resolution
    @Test
    void didResolutionCheck() {
        IssuerCheck c = new DidResolutionCheck();
        var cred = ldp(ISSUER, KEY_ID);
        assertEquals(CheckStatus.PASS, status(c, ctx(cred, TrustPolicy.registryStrict(), doc(ed25519(), ISSUER, true, true), null, false)));
        assertEquals(CheckStatus.PASS, status(c, ctx(cred, TrustPolicy.registryStrict(), new DidResolution.Malformed("X"), null, false)));
        assertEquals("DID_NOT_FOUND", reason(c, ctx(cred, TrustPolicy.registryStrict(), new DidResolution.NotFound(), null, false)));
        assertEquals(CheckStatus.FAIL, status(c, ctx(cred, TrustPolicy.registryStrict(), new DidResolution.Blocked("ADDRESS_NOT_PUBLIC"), null, false)));
        assertEquals(CheckStatus.INCONCLUSIVE, status(c, ctx(cred, TrustPolicy.registryStrict(), new DidResolution.Unavailable("DID_RESOLUTION_TIMEOUT"), null, false)));
        assertEquals(CheckStatus.INCONCLUSIVE, status(c, ctx(cred, TrustPolicy.registryStrict(), new DidResolution.Unsupported("U"), null, false)));
        assertEquals(CheckStatus.NOT_APPLICABLE, status(c, ctx(ldp("https://issuer.example.org", null), TrustPolicy.registryStrict(), null, null, false)));
        assertEquals(CheckStatus.NOT_EVALUATED, status(c, ctx(ldp("garbage", null), TrustPolicy.registryStrict(), null, null, false)));
    }

    @Test
    void blockedEndpointMessageDoesNotLeakInternals() {
        var r = new DidResolutionCheck().run(ctx(ldp(ISSUER, KEY_ID), TrustPolicy.registryStrict(), new DidResolution.Blocked("ADDRESS_NOT_PUBLIC"), null, false));
        assertFalse(r.message().contains("ADDRESS_NOT_PUBLIC"));
        assertFalse(r.message().matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*"));
    }

    // 3. DID document
    @Test
    void didDocumentCheck() {
        IssuerCheck c = new DidDocumentCheck();
        var cred = ldp(ISSUER, KEY_ID);
        assertEquals(CheckStatus.PASS, status(c, ctx(cred, TrustPolicy.registryStrict(), doc(ed25519(), ISSUER, true, true), null, false)));
        assertEquals("INVALID_DID_DOCUMENT", reason(c, ctx(cred, TrustPolicy.registryStrict(), new DidResolution.Malformed("DID_DOCUMENT_ID_MISMATCH"), null, false)));
        assertEquals(CheckStatus.NOT_EVALUATED, status(c, ctx(cred, TrustPolicy.registryStrict(), new DidResolution.Unavailable("X"), null, false)));
        assertEquals(CheckStatus.NOT_APPLICABLE, status(c, ctx(ldp("https://issuer.example.org", null), TrustPolicy.registryStrict(), null, null, false)));
    }

    // 4. public key
    @Test
    void publicKeyCheckPassesAndRecordsMatchedMethod() {
        var x = ctx(ldp(ISSUER, KEY_ID), TrustPolicy.registryStrict(), doc(ed25519(), ISSUER, true, true), null, false);
        assertEquals(CheckStatus.PASS, status(new PublicKeyCheck(), x));
        assertEquals(KEY_ID, x.matchedMethodId);
    }

    @Test
    void publicKeyCheckDetectsMismatchesAndSubstitution() {
        KeyPair kp = ed25519();
        var did = doc(kp, ISSUER, true, true);
        PublicKeyCheck c = new PublicKeyCheck();
        assertEquals("ISSUER_KEY_MISMATCH", reason(c, ctx(ldp(ISSUER, "did:web:evil.example.org#key-0"), TrustPolicy.registryStrict(), did, null, false)));
        assertEquals("ISSUER_KEY_MISMATCH", reason(c, ctx(ldp(ISSUER, ISSUER + "x#key-0"), TrustPolicy.registryStrict(), did, null, false)));
        assertEquals("KEY_NOT_IN_DID_DOCUMENT", reason(c, ctx(ldp(ISSUER, ISSUER + "#other"), TrustPolicy.registryStrict(), did, null, false)));
        assertEquals("KEY_CONTROLLER_MISMATCH", reason(c, ctx(ldp(ISSUER, KEY_ID), TrustPolicy.registryStrict(), doc(kp, "did:web:evil.example.org", true, true), null, false)));

        var substituted = new CredentialIssuerContext("jwt_vc", ISSUER, List.of(TYPE), KEY_ID, "someOtherKeyThumbprint", null);
        assertEquals("KEY_SUBSTITUTION", reason(c, ctx(substituted, TrustPolicy.registryStrict(), did, null, false)));
        assertEquals("NO_SIGNING_KEY_REFERENCE", reason(c, ctx(new CredentialIssuerContext("ldp_vc", ISSUER, List.of(TYPE), null, null, null), TrustPolicy.registryStrict(), did, null, false)));
        assertEquals(CheckStatus.NOT_EVALUATED, status(c, ctx(ldp(ISSUER, KEY_ID), TrustPolicy.registryStrict(), new DidResolution.NotFound(), null, false)));
    }

    @Test
    void publicKeyCheckFindsKeyByThumbprintWhenNoKidAndMatchesEquallyOnlyTheRightKey() throws Exception {
        KeyPair kp = ed25519();
        String thumb = io.inji.verify.issuer.crypto.KeyMaterial.fromPublicKey(kp.getPublic()).thumbprint();
        var did = doc(kp, ISSUER, true, true);
        var right = new CredentialIssuerContext("jwt_vc", ISSUER, List.of(TYPE), null, thumb, null);
        assertEquals(CheckStatus.PASS, status(new PublicKeyCheck(), ctx(right, TrustPolicy.registryStrict(), did, null, false)));
        var wrong = new CredentialIssuerContext("jwt_vc", ISSUER, List.of(TYPE), null, "nope", null);
        assertEquals("KEY_NOT_IN_DID_DOCUMENT", reason(new PublicKeyCheck(), ctx(wrong, TrustPolicy.registryStrict(), did, null, false)));
    }

    @Test
    void publicKeyCheckDistinguishesInvalidFromUnsupportedKeys() throws Exception {
        PublicKeyCheck c = new PublicKeyCheck();
        String base = "{\"id\":\"" + ISSUER + "\",\"verificationMethod\":[{\"id\":\"#key-0\",\"type\":\"T\",\"controller\":\"" + ISSUER + "\",%s}],\"assertionMethod\":[\"#key-0\"]}";
        var withPrivate = new DidResolution.Resolved(parser.parse(String.format(base, "\"publicKeyJwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY\",\"d\":\"AAAA\"}").getBytes(), ISSUER));
        assertEquals("INVALID_PUBLIC_KEY", reason(c, ctx(ldp(ISSUER, KEY_ID), TrustPolicy.registryStrict(), withPrivate, null, false)));
        var noKey = new DidResolution.Resolved(parser.parse(String.format(base, "\"publicKeyPem\":\"x\"").getBytes(), ISSUER));
        assertEquals(CheckStatus.INCONCLUSIVE, status(c, ctx(ldp(ISSUER, KEY_ID), TrustPolicy.registryStrict(), noKey, null, false)));
        var multibase = new DidResolution.Resolved(parser.parse(String.format(base, "\"publicKeyMultibase\":\"z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\"").getBytes(), ISSUER));
        assertEquals(CheckStatus.PASS, status(c, ctx(ldp(ISSUER, KEY_ID), TrustPolicy.registryStrict(), multibase, null, false)));
    }

    @Test
    void httpsIssuerKeyMustBeRegistered() {
        var cred = new CredentialIssuerContext("jwt_vc", "https://issuer.example.org", List.of(TYPE), null, "thumbA", null);
        PublicKeyCheck c = new PublicKeyCheck();
        IssuerMetadata withKey = new IssuerMetadata("https://issuer.example.org", "n", null, null, null, LifecycleStatus.ACTIVE, null, null, null, null, null, Set.of("thumbA"), null);
        IssuerMetadata otherKey = new IssuerMetadata("https://issuer.example.org", "n", null, null, null, LifecycleStatus.ACTIVE, null, null, null, null, null, Set.of("thumbB"), null);
        IssuerMetadata noKeys = new IssuerMetadata("https://issuer.example.org", "n", null, null, null, LifecycleStatus.ACTIVE, null, null, null, null, null, Set.of(), null);
        assertEquals(CheckStatus.PASS, status(c, ctx(cred, TrustPolicy.registryStrict(), null, found(withKey), true)));
        assertEquals("KEY_SUBSTITUTION", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, found(otherKey), true)));
        assertEquals("NO_INDEPENDENT_KEY_SOURCE", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, found(noKeys), true)));
        assertEquals("NO_INDEPENDENT_KEY_SOURCE", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, null, false)));
        assertEquals("NO_INDEPENDENT_KEY_SOURCE", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, new RegistryLookup.NotFound("r"), true)));
        assertEquals("REGISTRY_TIMEOUT", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, new RegistryLookup.Unavailable("r", "REGISTRY_TIMEOUT"), true)));
    }

    // 5. signature key authorised
    @Test
    void signatureKeyAuthorizedRequiresAssertionMethodAndMatchingPurpose() {
        KeyPair kp = ed25519();
        SignatureKeyAuthorizedCheck c = new SignatureKeyAuthorizedCheck();
        for (boolean assertion : new boolean[]{true, false}) {
            var x = ctx(ldp(ISSUER, KEY_ID), TrustPolicy.registryStrict(), doc(kp, ISSUER, assertion, true), null, false);
            x.results.put(CheckId.PUBLIC_KEY_VALID, new PublicKeyCheck().run(x));
            assertEquals(assertion ? CheckStatus.PASS : CheckStatus.FAIL, status(c, x));
            if (!assertion) assertEquals("KEY_NOT_AUTHORIZED_FOR_ASSERTION", reason(c, x));
        }
        var wrongPurpose = new CredentialIssuerContext("ldp_vc", ISSUER, List.of(TYPE), KEY_ID, null, "authentication");
        var x = ctx(wrongPurpose, TrustPolicy.registryStrict(), doc(kp, ISSUER, true, true), null, false);
        x.results.put(CheckId.PUBLIC_KEY_VALID, new PublicKeyCheck().run(x));
        assertEquals("PROOF_PURPOSE_MISMATCH", reason(c, x));
    }

    @Test
    void signatureKeyAuthorizedIsNotEvaluatedWithoutKeyBinding() {
        var x = ctx(ldp(ISSUER, KEY_ID), TrustPolicy.registryStrict(), doc(ed25519(), ISSUER, true, true), null, false);
        assertEquals(CheckStatus.NOT_EVALUATED, status(new SignatureKeyAuthorizedCheck(), x));
        x.results.put(CheckId.PUBLIC_KEY_VALID, CheckResult.fail(CheckId.PUBLIC_KEY_VALID, "KEY_SUBSTITUTION", "f"));
        assertEquals(CheckStatus.NOT_EVALUATED, status(new SignatureKeyAuthorizedCheck(), x));
    }

    // 6. registered
    @Test
    void issuerRegisteredCheck() {
        IssuerCheck c = new IssuerRegisteredCheck();
        var cred = ldp(ISSUER, KEY_ID);
        assertEquals(CheckStatus.PASS, status(c, ctx(cred, TrustPolicy.registryStrict(), null, found(metadata(ISSUER, LifecycleStatus.ACTIVE)), true)));
        assertEquals("ISSUER_NOT_REGISTERED", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, new RegistryLookup.NotFound("r"), true)));
        assertEquals(CheckStatus.INCONCLUSIVE, status(c, ctx(cred, TrustPolicy.registryStrict(), null, new RegistryLookup.Unavailable("r", "REGISTRY_UNAVAILABLE"), true)));
        assertEquals("REGISTRY_NOT_CONFIGURED", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, null, false)));
        assertEquals(CheckStatus.NOT_EVALUATED, status(c, ctx(ldp("garbage", null), TrustPolicy.registryStrict(), null, null, true)));
    }

    // 7. active
    @Test
    void issuerActiveCheckCoversLifecycleAndValidityWindow() {
        IssuerCheck c = new IssuerActiveCheck();
        var cred = ldp(ISSUER, KEY_ID);
        assertEquals(CheckStatus.PASS, status(c, ctx(cred, TrustPolicy.registryStrict(), null, found(metadata(ISSUER, LifecycleStatus.ACTIVE)), true)));
        assertEquals("ISSUER_SUSPENDED", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, found(metadata(ISSUER, LifecycleStatus.SUSPENDED)), true)));
        assertEquals("ISSUER_REVOKED", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, found(metadata(ISSUER, LifecycleStatus.REVOKED)), true)));
        assertEquals("ISSUER_DEACTIVATED", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, found(metadata(ISSUER, LifecycleStatus.DEACTIVATED)), true)));
        var m = metadata(ISSUER, LifecycleStatus.ACTIVE);
        var expired = new IssuerMetadata(ISSUER, "n", null, null, null, LifecycleStatus.ACTIVE, null, NOW.minusSeconds(3600), null, null, null, null, null);
        var future = new IssuerMetadata(ISSUER, "n", null, null, null, LifecycleStatus.ACTIVE, NOW.plusSeconds(3600), null, null, null, null, null, null);
        var justExpiredWithinSkew = new IssuerMetadata(ISSUER, "n", null, null, null, LifecycleStatus.ACTIVE, null, NOW.minusSeconds(30), null, null, null, null, null);
        assertEquals("ISSUER_VALIDITY_EXPIRED", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, found(expired), true)));
        assertEquals("ISSUER_NOT_YET_VALID", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, found(future), true)));
        assertEquals(CheckStatus.PASS, status(c, ctx(cred, TrustPolicy.registryStrict(), null, found(justExpiredWithinSkew), true)), "60s clock skew tolerated");
        assertEquals(CheckStatus.NOT_EVALUATED, status(c, ctx(cred, TrustPolicy.registryStrict(), null, new RegistryLookup.NotFound("r"), true)));
    }

    // 8. accreditation
    @Test
    void accreditationCheck() {
        IssuerCheck c = new AccreditationCheck();
        var cred = ldp(ISSUER, KEY_ID);
        assertEquals(CheckStatus.PASS, status(c, ctx(cred, TrustPolicy.registryStrict(), null, found(metadata(ISSUER, LifecycleStatus.ACTIVE)), true)));
        Instant from = Instant.parse("2026-01-01T00:00:00Z");
        IssuerMetadata expired = withAcc(new Accreditation("a", "x", LifecycleStatus.ACTIVE, from, NOW.minusSeconds(86400)));
        IssuerMetadata future = withAcc(new Accreditation("a", "x", LifecycleStatus.ACTIVE, NOW.plusSeconds(86400), null));
        IssuerMetadata revoked = withAcc(new Accreditation("a", "x", LifecycleStatus.REVOKED, from, null));
        IssuerMetadata none = withAcc();
        assertEquals("ACCREDITATION_EXPIRED", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, found(expired), true)));
        assertEquals("ACCREDITATION_NOT_YET_VALID", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, found(future), true)));
        assertEquals("ACCREDITATION_NOT_ACTIVE", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, found(revoked), true)));
        assertEquals("NO_ACCREDITATION", reason(c, ctx(cred, TrustPolicy.registryStrict(), null, found(none), true)));
        // one valid accreditation is enough even if another has lapsed
        IssuerMetadata mixed = withAcc(new Accreditation("old", "x", LifecycleStatus.ACTIVE, from, NOW.minusSeconds(86400)), new Accreditation("new", "x", LifecycleStatus.ACTIVE, from, null));
        assertEquals(CheckStatus.PASS, status(c, ctx(cred, TrustPolicy.registryStrict(), null, found(mixed), true)));
    }

    private IssuerMetadata withAcc(Accreditation... a) {
        return new IssuerMetadata(ISSUER, "n", null, null, null, LifecycleStatus.ACTIVE, null, null, List.of(a), null, null, null, null);
    }

    // 9. credential type
    @Test
    void credentialTypeAuthorizedCheck() {
        IssuerCheck c = new CredentialTypeAuthorizedCheck();
        var reg = found(metadata(ISSUER, LifecycleStatus.ACTIVE));
        assertEquals(CheckStatus.PASS, status(c, ctx(ldp(ISSUER, KEY_ID), TrustPolicy.registryStrict(), null, reg, true)));
        var other = new CredentialIssuerContext("ldp_vc", ISSUER, List.of("VerifiableCredential", "DrivingLicense"), KEY_ID, null, null);
        assertEquals("CREDENTIAL_TYPE_NOT_AUTHORIZED", reason(c, ctx(other, TrustPolicy.registryStrict(), null, reg, true)));
        var oneOfTwo = new CredentialIssuerContext("ldp_vc", ISSUER, List.of("VerifiableCredential", TYPE, "DrivingLicense"), KEY_ID, null, null);
        assertEquals("CREDENTIAL_TYPE_NOT_AUTHORIZED", reason(c, ctx(oneOfTwo, TrustPolicy.registryStrict(), null, reg, true)), "every claimed type must be authorised");
        var generic = new CredentialIssuerContext("ldp_vc", ISSUER, List.of("VerifiableCredential"), KEY_ID, null, null);
        assertEquals("NO_CREDENTIAL_TYPE", reason(c, ctx(generic, TrustPolicy.registryStrict(), null, reg, true)));
        var wildcard = new IssuerMetadata(ISSUER, "n", null, null, null, LifecycleStatus.ACTIVE, null, null, null, null, Set.of("*"), null, null);
        assertEquals(CheckStatus.PASS, status(c, ctx(other, TrustPolicy.registryStrict(), null, found(wildcard), true)));
    }

    // 10. trust framework
    @Test
    void trustFrameworkCheck() {
        IssuerCheck c = new TrustFrameworkCheck();
        var cred = ldp(ISSUER, KEY_ID);
        var reg = found(metadata(ISSUER, LifecycleStatus.ACTIVE));
        assertEquals(CheckStatus.PASS, status(c, ctx(cred, TrustPolicy.trustFramework(Set.of("example-trust-framework")), null, reg, true)));
        assertEquals("TRUST_FRAMEWORK_NOT_APPROVED", reason(c, ctx(cred, TrustPolicy.trustFramework(Set.of("another-framework")), null, reg, true)));
        assertEquals("POLICY_MISCONFIGURED", reason(c, ctx(cred, TrustPolicy.trustFramework(Set.of()), null, reg, true)), "required but nothing approved must fail closed");
        assertEquals(CheckStatus.NOT_APPLICABLE, status(c, ctx(cred, TrustPolicy.registryStrict(), null, reg, true)));
    }
}
