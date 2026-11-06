package io.inji.verify.issuer.registry;

import io.inji.verify.issuer.TestFixtures.FakeFetcher;
import io.inji.verify.issuer.metadata.IssuerMetadataService;
import io.inji.verify.issuer.metadata.TtlCache;
import io.inji.verify.issuer.model.IssuerMetadata;
import io.inji.verify.issuer.model.LifecycleStatus;
import io.inji.verify.issuer.net.FetchResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static io.inji.verify.issuer.TestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class RegistryTest {

    static final String RECORD = "{\"issuerId\":\"" + ISSUER + "\",\"name\":\"Example Government Authority\",\"legalName\":\"Example Government Authority Ltd\","
            + "\"organizationType\":\"GOVERNMENT\",\"jurisdiction\":\"IN\",\"status\":\"ACTIVE\",\"validFrom\":\"2026-01-01\",\"validUntil\":\"2027-12-31\","
            + "\"accreditations\":[{\"id\":\"acc-1\",\"authority\":\"NAB\",\"status\":\"ACTIVE\",\"validFrom\":\"2026-01-01\",\"validUntil\":\"2027-12-31\"}],"
            + "\"trustFrameworks\":[\"example-trust-framework\"],\"authorizedCredentialTypes\":[\"NationalIdCredential\"],\"keyThumbprints\":[\"abc\"]}";

    // ---- parser ----
    @Test
    void parsesCanonicalRecordAndTreatsDateOnlyValidUntilAsInclusive() throws Exception {
        IssuerMetadata m = IssuerMetadataParser.parse(json(RECORD));
        assertEquals("Example Government Authority", m.displayName());
        assertEquals(LifecycleStatus.ACTIVE, m.status());
        assertEquals(Instant.parse("2028-01-01T00:00:00Z"), m.validUntil(), "valid through the whole of 2027-12-31");
        assertEquals(Instant.parse("2026-01-01T00:00:00Z"), m.validFrom());
        assertTrue(m.authorizedCredentialTypes().contains("NationalIdCredential"));
        assertEquals(1, m.accreditations().size());
    }

    @Test
    void rejectsMalformedMetadata() {
        for (String bad : new String[]{"[]", "{}", "{\"issuerId\":\"x\"}", "{\"issuerId\":\"x\",\"status\":\"WHATEVER\"}",
                "{\"issuerId\":5,\"status\":\"ACTIVE\"}", "{\"issuerId\":\"x\",\"status\":\"ACTIVE\",\"validUntil\":\"tomorrow\"}",
                "{\"issuerId\":\"x\",\"status\":\"ACTIVE\",\"trustFrameworks\":\"a\"}", "{\"issuerId\":\"x\",\"status\":\"ACTIVE\",\"trustFrameworks\":[1]}",
                "{\"issuerId\":\"x\",\"status\":\"ACTIVE\",\"accreditations\":[{\"status\":\"BAD\"}]}",
                "{\"issuerId\":\"" + "x".repeat(600) + "\",\"status\":\"ACTIVE\"}"}) {
            assertThrows(MalformedMetadataException.class, () -> IssuerMetadataParser.parse(json(bad)), bad);
        }
    }

    // ---- static ----
    @Test
    void staticRegistryFindsAndMissesExactly() throws Exception {
        var reg = StaticIssuerTrustRegistry.fromJson(json("{\"registryId\":\"gov\",\"issuers\":[" + RECORD + "]}"), "file", MAPPER);
        assertTrue(reg.lookup(ISSUER) instanceof RegistryLookup.Found);
        assertEquals("gov", reg.registryId());
        assertTrue(reg.lookup("did:web:other.example.org") instanceof RegistryLookup.NotFound);
        assertTrue(reg.lookup(ISSUER.toUpperCase()) instanceof RegistryLookup.NotFound, "no fuzzy matching");
    }

    @Test
    void malformedStaticRegistryFailsStartupInsteadOfBeingEmpty() {
        assertThrows(MalformedMetadataException.class, () -> StaticIssuerTrustRegistry.fromJson(json("{\"issuers\":[{\"issuerId\":\"x\"}]}"), "f", MAPPER));
        assertThrows(MalformedMetadataException.class, () -> StaticIssuerTrustRegistry.fromJson(json("{}"), "f", MAPPER));
    }

    // ---- REST ----
    private static final String ENDPOINT = "https://registry.example.org/api/issuers/" + java.net.URLEncoder.encode(ISSUER, java.nio.charset.StandardCharsets.UTF_8);

    @Test
    void restRegistryMapsResponsesWithoutConfusingOutagesWithAbsence() {
        RestIssuerTrustRegistry ok = new RestIssuerTrustRegistry("rest", "https://registry.example.org/api/", new FakeFetcher().json(ENDPOINT, RECORD));
        assertTrue(ok.lookup(ISSUER) instanceof RegistryLookup.Found);

        assertTrue(new RestIssuerTrustRegistry("rest", "https://registry.example.org/api", new FakeFetcher().result(ENDPOINT, FetchResult.of(FetchResult.Outcome.NOT_FOUND, "HTTP_404")))
                .lookup(ISSUER) instanceof RegistryLookup.NotFound);

        for (FetchResult.Outcome o : new FetchResult.Outcome[]{FetchResult.Outcome.HTTP_ERROR, FetchResult.Outcome.NETWORK_ERROR, FetchResult.Outcome.BLOCKED, FetchResult.Outcome.TOO_LARGE}) {
            assertTrue(new RestIssuerTrustRegistry("rest", "https://registry.example.org/api", new FakeFetcher().result(ENDPOINT, FetchResult.of(o, "x")))
                    .lookup(ISSUER) instanceof RegistryLookup.Unavailable, o.name());
        }
        RegistryLookup.Unavailable timeout = (RegistryLookup.Unavailable) new RestIssuerTrustRegistry("rest", "https://registry.example.org/api", new FakeFetcher()).lookup(ISSUER);
        assertEquals("REGISTRY_TIMEOUT", timeout.reasonCode());
    }

    @Test
    void restRegistryRejectsMalformedAndMismatchedResponses() {
        var garbage = new RestIssuerTrustRegistry("rest", "https://registry.example.org/api", new FakeFetcher().json(ENDPOINT, "{\"issuerId\":"));
        assertEquals("MALFORMED_REGISTRY_RESPONSE", ((RegistryLookup.Unavailable) garbage.lookup(ISSUER)).reasonCode());
        // a response about a different issuer must never vouch for the one asked about
        String other = RECORD.replace(ISSUER, "did:web:other.example.org");
        var mismatch = new RestIssuerTrustRegistry("rest", "https://registry.example.org/api", new FakeFetcher().json(ENDPOINT, other));
        assertEquals("REGISTRY_RESPONSE_MISMATCH", ((RegistryLookup.Unavailable) mismatch.lookup(ISSUER)).reasonCode());
    }

    @Test
    void restRegistryUrlEncodesIssuerIdSoItCannotEscapeThePath() {
        FakeFetcher f = new FakeFetcher();
        new RestIssuerTrustRegistry("rest", "https://registry.example.org/api", f).lookup("did:web:a.example/../../admin?x=1");
        assertEquals(1, f.requested.size());
        assertTrue(f.requested.get(0).startsWith("https://registry.example.org/api/issuers/did%3Aweb%3Aa.example%2F..%2F..%2Fadmin%3Fx%3D1"), f.requested.get(0));
    }

    // ---- metadata service ----
    static class CountingRegistry implements IssuerTrustRegistry {
        final String id;
        RegistryLookup answer;
        int calls;

        CountingRegistry(String id, RegistryLookup answer) {
            this.id = id;
            this.answer = answer;
        }

        public String registryId() {
            return id;
        }

        public RegistryLookup lookup(String issuerId) {
            calls++;
            return answer;
        }
    }

    private IssuerMetadataService service(Duration maxAge, IssuerTrustRegistry... regs) {
        return new IssuerMetadataService(List.of(regs), new TtlCache<>(10, CLOCK), Duration.ofMinutes(5), Duration.ofMinutes(1), maxAge, CLOCK);
    }

    @Test
    void cachesFoundAndNotFoundButNeverUnavailable() {
        CountingRegistry found = new CountingRegistry("r", new RegistryLookup.Found("r", metadata(ISSUER, LifecycleStatus.ACTIVE)));
        IssuerMetadataService s = service(Duration.ZERO, found);
        s.lookup(ISSUER);
        s.lookup(ISSUER);
        assertEquals(1, found.calls);
        s.invalidate(ISSUER);
        s.lookup(ISSUER);
        assertEquals(2, found.calls);

        CountingRegistry down = new CountingRegistry("r", new RegistryLookup.Unavailable("r", "REGISTRY_TIMEOUT"));
        IssuerMetadataService s2 = service(Duration.ZERO, down);
        s2.lookup(ISSUER);
        s2.lookup(ISSUER);
        assertEquals(2, down.calls, "outages must not be cached");
    }

    @Test
    void firstHitWinsAndOutageBeatsNotFound() {
        CountingRegistry miss = new CountingRegistry("a", new RegistryLookup.NotFound("a"));
        CountingRegistry hit = new CountingRegistry("b", new RegistryLookup.Found("b", metadata(ISSUER, LifecycleStatus.ACTIVE)));
        assertEquals("b", ((RegistryLookup.Found) service(Duration.ZERO, miss, hit).lookup(ISSUER)).registryId());

        CountingRegistry down = new CountingRegistry("c", new RegistryLookup.Unavailable("c", "REGISTRY_UNAVAILABLE"));
        assertTrue(service(Duration.ZERO, miss, down).lookup(ISSUER) instanceof RegistryLookup.Unavailable,
                "one registry down + others say not found is NOT 'not found'");
        assertTrue(service(Duration.ZERO, new CountingRegistry("a", new RegistryLookup.NotFound("a"))).lookup(ISSUER) instanceof RegistryLookup.NotFound);
    }

    @Test
    void staleMetadataIsNotUsed() {
        IssuerMetadata old = new IssuerMetadata(ISSUER, "n", null, null, null, LifecycleStatus.ACTIVE, null, null, null, null, null, null, NOW.minus(Duration.ofDays(3)));
        RegistryLookup r = service(Duration.ofDays(1), new CountingRegistry("r", new RegistryLookup.Found("r", old))).lookup(ISSUER);
        assertEquals("STALE_REGISTRY_METADATA", ((RegistryLookup.Unavailable) r).reasonCode());
        assertTrue(service(Duration.ofDays(7), new CountingRegistry("r", new RegistryLookup.Found("r", old))).lookup(ISSUER) instanceof RegistryLookup.Found);
    }

    @Test
    void registryThrowingIsContainedAndEmptyConfigIsReported() {
        IssuerTrustRegistry boom = new IssuerTrustRegistry() {
            public String registryId() {
                return "boom";
            }

            public RegistryLookup lookup(String id) {
                throw new IllegalStateException("secret internal detail");
            }
        };
        assertTrue(service(Duration.ZERO, boom).lookup(ISSUER) instanceof RegistryLookup.Unavailable);
        IssuerMetadataService none = service(Duration.ZERO);
        assertFalse(none.isRegistryConfigured());
        assertEquals("REGISTRY_NOT_CONFIGURED", ((RegistryLookup.Unavailable) none.lookup(ISSUER)).reasonCode());
    }

    @Test
    void ttlCacheEvictsLeastRecentlyUsed() {
        TtlCache<String, Integer> c = new TtlCache<>(2, CLOCK);
        c.put("a", 1, Duration.ofMinutes(1));
        c.put("b", 2, Duration.ofMinutes(1));
        c.get("a");
        c.put("c", 3, Duration.ofMinutes(1));
        assertTrue(c.get("b").isEmpty());
        assertTrue(c.get("a").isPresent());
        c.put("d", 4, Duration.ZERO);
        assertTrue(c.get("d").isEmpty(), "zero TTL stores nothing");
        assertEquals(2, c.size());
    }
}
