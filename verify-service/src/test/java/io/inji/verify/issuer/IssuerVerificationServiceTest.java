package io.inji.verify.issuer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.inji.verify.issuer.TestFixtures.FakeFetcher;
import io.inji.verify.issuer.did.*;
import io.inji.verify.issuer.engine.IssuerVerificationEngine;
import io.inji.verify.issuer.extract.CredentialIssuerExtractor;
import io.inji.verify.issuer.metadata.IssuerMetadataService;
import io.inji.verify.issuer.metadata.TtlCache;
import io.inji.verify.issuer.model.*;
import io.inji.verify.issuer.policy.TrustPolicy;
import io.inji.verify.issuer.policy.TrustPolicyEngine;
import io.inji.verify.issuer.registry.StaticIssuerTrustRegistry;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Duration;
import java.util.List;

import static io.inji.verify.issuer.TestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class IssuerVerificationServiceTest {

    private final KeyPair key = ed25519();

    private IssuerVerificationService service(boolean runByDefault, boolean enforce) {
        FakeFetcher f = new FakeFetcher().json("https://issuer.example.org/.well-known/did.json", didDocument(ISSUER, KEY_ID, key.getPublic(), ISSUER, true, true));
        var engine = new IssuerVerificationEngine(new DidResolvers(List.of(new DidWebResolver(f, new DidDocumentParser()))),
                new IssuerMetadataService(List.of(new StaticIssuerTrustRegistry("example-registry", List.of(metadata(ISSUER, LifecycleStatus.ACTIVE)))),
                        new TtlCache<>(10, CLOCK), Duration.ofMinutes(5), Duration.ofMinutes(1), Duration.ZERO, CLOCK),
                new TrustPolicyEngine(), TrustPolicy.registryStrict(), CLOCK, Duration.ofSeconds(60));
        return new IssuerVerificationService(new CredentialIssuerExtractor(), engine, runByDefault, enforce);
    }

    private static final String VC = "{\"type\":[\"VerifiableCredential\",\"NationalIdCredential\"],\"issuer\":\"did:web:issuer.example.org\","
            + "\"proof\":{\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":\"did:web:issuer.example.org#key-0\"}}";

    @Test
    void verifiesCredentialEndToEndFromRawJson() {
        var r = service(true, false).verify(VC);
        assertEquals(TrustStatus.TRUSTED, r.overallStatus());
        assertEquals(ISSUER, r.issuerId());
    }

    @Test
    void requestFlagOverridesServerDefault() {
        IssuerVerificationService on = service(true, false), off = service(false, false);
        assertTrue(on.shouldVerify(null));
        assertFalse(on.shouldVerify(false));
        assertFalse(off.shouldVerify(null));
        assertTrue(off.shouldVerify(true));
    }

    @Test
    void enforcementFlagAndTrustHelper() {
        assertTrue(service(true, true).isEnforcing());
        assertFalse(service(true, false).isEnforcing());
        assertTrue(service(true, true).isTrusted(service(true, true).verify(VC)));
        assertFalse(service(true, true).isTrusted(null));
    }

    @Test
    void unsupportedAndMalformedCredentialsAreInconclusiveNotErrors() {
        var cwt = service(true, true).verify("D28441A0A0A0");
        assertEquals(TrustStatus.INCONCLUSIVE, cwt.overallStatus());
        assertEquals("UNSUPPORTED_CREDENTIAL_FORMAT", cwt.failureReasons().get(0));
        var junk = service(true, true).verify("{not json");
        assertEquals(TrustStatus.INCONCLUSIVE, junk.overallStatus());
        assertEquals(TrustStatus.INCONCLUSIVE, service(true, true).verify(null).overallStatus());
    }

    @Test
    void resultSerializesWithStableApiShape() throws Exception {
        ObjectMapper m = new ObjectMapper().registerModule(new JavaTimeModule()).disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        var json = m.readTree(m.writeValueAsString(service(true, false).verify(VC)));
        assertEquals(ISSUER, json.get("issuerId").asText());
        assertEquals("TRUSTED", json.get("overallStatus").asText());
        assertEquals("TRUSTED_ISSUER", json.get("displayStatus").asText());
        assertEquals("A", json.get("policy").asText());
        assertEquals("VERIFIED", json.get("cryptographicAuthenticity").asText());
        assertEquals("TRUSTED", json.get("organizationalTrust").asText());
        assertEquals("2026-11-06T10:00:00Z", json.get("verifiedAt").asText());
        assertEquals("example-registry", json.get("trustRegistry").get("registryId").asText());
        assertEquals("ACTIVE", json.get("accreditation").get("status").asText());
        assertTrue(json.get("failureReasons").isArray() && json.get("failureReasons").size() == 0);
        var first = json.get("checks").get(0);
        assertEquals("ISSUER_IDENTIFIER_VALID", first.get("id").asText());
        assertEquals("PASS", first.get("status").asText());
        assertTrue(first.has("reasonCode") && first.has("message"));
        assertEquals(10, json.get("checks").size());
    }
}
