package io.inji.verify.issuer.registry;

import com.fasterxml.jackson.databind.JsonNode;
import io.inji.verify.issuer.net.FetchResult;
import io.inji.verify.issuer.net.HttpFetcher;
import org.junit.jupiter.api.Test;

import java.util.*;

import static io.inji.verify.issuer.TestFixtures.ISSUER;
import static io.inji.verify.issuer.registry.TrqpTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/** TRQP v2.0 HTTPS binding as documented by ToIP; no live registry was available when these were written. */
class TrqpRegistryTest {

    private TrqpIssuerTrustRegistry registry(StubFetcher f) {
        return new TrqpIssuerTrustRegistry("trqp-registry", "https://registry.example.org/", AUTHORITY, null, f);
    }

    @Test
    void sendsOneSpecShapedAuthorizationQueryPerTypeAndSkipsVerifiableCredential() {
        StubFetcher f = new StubFetcher();
        f.byResource = r -> ok(answer(r, true));
        var result = registry(f).lookup(ISSUER, List.of("VerifiableCredential", "Degree", "Degree", "Other"));

        assertEquals(2, f.bodies.size(), "VerifiableCredential skipped, duplicates collapsed");
        assertEquals("https://registry.example.org/authorization", f.uris.get(0).toString());
        JsonNode q = f.bodies.get(0);
        assertEquals(AUTHORITY, q.get("authority_id").asText());
        assertEquals(ISSUER, q.get("entity_id").asText());
        assertEquals("issue", q.get("action").asText(), "default action");
        assertEquals("Degree", q.get("resource").asText());
        assertEquals(4, q.size(), "no optional context is sent");

        var found = assertInstanceOf(RegistryLookup.Found.class, result);
        assertEquals(Set.of("Degree", "Other"), found.metadata().authorizedCredentialTypes());
        assertEquals("trqp-registry", found.registryId());
        assertNull(found.metadata().displayName(), "TRQP carries no name; none is invented");
        assertTrue(found.metadata().accreditations().isEmpty());
        assertEquals(java.time.Instant.parse("2026-11-06T09:59:00Z"), found.metadata().asOf());
    }

    @Test
    void partialAuthorizationKeepsOnlyAuthorizedTypes() {
        StubFetcher f = new StubFetcher();
        f.byResource = r -> ok(answer(r, r.equals("Degree")));
        var found = assertInstanceOf(RegistryLookup.Found.class, registry(f).lookup(ISSUER, List.of("Degree", "Other")));
        assertEquals(Set.of("Degree"), found.metadata().authorizedCredentialTypes());
    }

    @Test
    void deniedForEveryTypeIsNotFound() {
        StubFetcher f = new StubFetcher();
        f.byResource = r -> ok(answer(r, false));
        assertInstanceOf(RegistryLookup.NotFound.class, registry(f).lookup(ISSUER, List.of("Degree")));
    }

    @Test
    void problemDetails404MeansUnknownToTheAuthority() {
        StubFetcher f = new StubFetcher();
        f.byResource = r -> problem404();
        assertInstanceOf(RegistryLookup.NotFound.class, registry(f).lookup(ISSUER, List.of("Degree")));
    }

    @Test
    void bare404IsAWrongUrlNotEvidenceAgainstTheIssuer() {
        StubFetcher f = new StubFetcher();
        f.byResource = r -> new FetchResult(FetchResult.Outcome.NOT_FOUND, 404, "<html>Not Found</html>".getBytes(), "HTTP_404");
        var u = assertInstanceOf(RegistryLookup.Unavailable.class, registry(f).lookup(ISSUER, List.of("Degree")));
        assertEquals("REGISTRY_ENDPOINT_NOT_FOUND", u.reasonCode());

        f.byResource = r -> new FetchResult(FetchResult.Outcome.NOT_FOUND, 404, "{\"status\":404,\"error\":\"Not Found\"}".getBytes(), "HTTP_404");
        assertInstanceOf(RegistryLookup.Unavailable.class, registry(f).lookup(ISSUER, List.of("Degree")), "framework default error JSON is not a TRQP problem");
    }

    @Test
    void anyFailureForAnyTypeMakesTheWholeAnswerUnavailable() {
        StubFetcher f = new StubFetcher();
        f.byResource = r -> r.equals("Other") ? FetchResult.of(FetchResult.Outcome.TIMEOUT, "TIMEOUT") : ok(answer(r, true));
        var u = assertInstanceOf(RegistryLookup.Unavailable.class, registry(f).lookup(ISSUER, List.of("Degree", "Other")));
        assertEquals("REGISTRY_TIMEOUT", u.reasonCode());

        for (FetchResult.Outcome o : List.of(FetchResult.Outcome.HTTP_ERROR, FetchResult.Outcome.NETWORK_ERROR, FetchResult.Outcome.BLOCKED, FetchResult.Outcome.TOO_LARGE)) {
            f.byResource = r -> FetchResult.of(o, o.name());
            assertInstanceOf(RegistryLookup.Unavailable.class, registry(f).lookup(ISSUER, List.of("Degree")), o.name());
        }
    }

    @Test
    void malformedOrMismatchingAnswersAreUnavailable() {
        StubFetcher f = new StubFetcher();
        for (String bad : List.of("not json", "[]", "{}", "{\"authorized\":\"yes\"}", "{\"authorized\":1}",
                "{\"authorized\":true,\"entity_id\":\"did:web:someone-else.example.org\"}",
                "{\"authorized\":true,\"authority_id\":\"did:web:other-authority.example.org\"}",
                "{\"authorized\":true,\"resource\":\"SomethingElse\"}",
                "{\"authorized\":true,\"authorized\":false}")) {
            f.byResource = r -> ok(bad);
            var u = assertInstanceOf(RegistryLookup.Unavailable.class, registry(f).lookup(ISSUER, List.of("Degree")), bad);
            assertTrue(u.reasonCode().startsWith("MALFORMED") || u.reasonCode().startsWith("REGISTRY_RESPONSE_MISMATCH"), bad + " -> " + u.reasonCode());
        }
    }

    @Test
    void echoFieldsAreOptionalButMustMatchWhenPresent() {
        StubFetcher f = new StubFetcher();
        f.byResource = r -> ok("{\"authorized\":true}");
        assertInstanceOf(RegistryLookup.Found.class, registry(f).lookup(ISSUER, List.of("Degree")));
    }

    @Test
    void nothingToAskIsUnavailableNotUntrusted() {
        StubFetcher f = new StubFetcher();
        var r = registry(f);
        assertEquals("NO_CREDENTIAL_TYPE_TO_QUERY", assertInstanceOf(RegistryLookup.Unavailable.class, r.lookup(ISSUER, List.of("VerifiableCredential"))).reasonCode());
        assertEquals("NO_CREDENTIAL_TYPE_TO_QUERY", assertInstanceOf(RegistryLookup.Unavailable.class, r.lookup(ISSUER, null)).reasonCode());
        assertEquals("CREDENTIAL_TYPE_REQUIRED", assertInstanceOf(RegistryLookup.Unavailable.class, r.lookup(ISSUER)).reasonCode());
        assertTrue(f.bodies.isEmpty());
    }

    @Test
    void tooManyTypesAreRefusedBeforeAnyRequest() {
        StubFetcher f = new StubFetcher();
        List<String> many = new ArrayList<>();
        for (int i = 0; i <= TrqpIssuerTrustRegistry.MAX_TYPES; i++) many.add("T" + i);
        assertEquals("TOO_MANY_CREDENTIAL_TYPES", assertInstanceOf(RegistryLookup.Unavailable.class, registry(f).lookup(ISSUER, many)).reasonCode());
        assertTrue(f.bodies.isEmpty());
    }

    @Test
    void absurdTypeNamesAreNeverSentAndCountAsNotAuthorized() {
        StubFetcher f = new StubFetcher();
        f.byResource = r -> ok(answer(r, true));
        var r = registry(f).lookup(ISSUER, List.of("x".repeat(TrqpIssuerTrustRegistry.MAX_FIELD_LENGTH + 1), "bad\nname", " "));
        assertInstanceOf(RegistryLookup.NotFound.class, r);
        assertTrue(f.bodies.isEmpty());
    }

    @Test
    void typeWithJsonMetacharactersIsSentAsDataNotStructure() {
        StubFetcher f = new StubFetcher();
        f.byResource = r -> ok("{\"authorized\":true}");
        registry(f).lookup(ISSUER, List.of("A\",\"authorized\":true,\"x\":\""));
        assertEquals(4, f.bodies.get(0).size());
        assertEquals("A\",\"authorized\":true,\"x\":\"", f.bodies.get(0).get("resource").asText());
    }

    @Test
    void customActionIsUsedAndConfigurationIsValidated() {
        StubFetcher f = new StubFetcher();
        f.byResource = r -> ok("{\"authorized\":true}");
        new TrqpIssuerTrustRegistry("r", "https://registry.example.org", AUTHORITY, "certify", f).lookup(ISSUER, List.of("Degree"));
        assertEquals("certify", f.bodies.get(0).get("action").asText());
        assertEquals("https://registry.example.org/authorization", f.uris.get(0).toString());
        assertThrows(IllegalArgumentException.class, () -> new TrqpIssuerTrustRegistry("r", " ", AUTHORITY, null, f));
        assertThrows(IllegalArgumentException.class, () -> new TrqpIssuerTrustRegistry("r", "https://x.example.org", null, null, f));
    }

    @Test
    void declaresItselfCredentialTypeAware() {
        assertTrue(registry(new StubFetcher()).credentialTypeAware());
        assertFalse(new StaticIssuerTrustRegistry("s", List.of()).credentialTypeAware());
    }
}
