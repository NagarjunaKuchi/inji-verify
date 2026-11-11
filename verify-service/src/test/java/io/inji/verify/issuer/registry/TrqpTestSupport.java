package io.inji.verify.issuer.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.issuer.net.FetchResult;
import io.inji.verify.issuer.net.HttpFetcher;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static io.inji.verify.issuer.TestFixtures.ISSUER;

/** Shared stubs for TRQP tests. */
public final class TrqpTestSupport {
    private TrqpTestSupport() {
    }

    public static final String AUTHORITY = "did:web:authority.example.org";
    public static final ObjectMapper M = new ObjectMapper();

    /** Answers POSTs by resource; records what was sent. */
    public static final class StubFetcher implements HttpFetcher {
        public final List<URI> uris = new ArrayList<>();
        public final List<JsonNode> bodies = new ArrayList<>();
        public Function<String, FetchResult> byResource = r -> FetchResult.of(FetchResult.Outcome.TIMEOUT, "TIMEOUT");

        @Override
        public FetchResult fetch(URI uri) {
            throw new AssertionError("TRQP must not use GET");
        }

        @Override
        public FetchResult post(URI uri, byte[] jsonBody) {
            try {
                JsonNode n = M.readTree(jsonBody);
                uris.add(uri);
                bodies.add(n);
                return byResource.apply(n.get("resource").asText());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    public static FetchResult ok(String json) {
        return FetchResult.ok(200, json.getBytes(StandardCharsets.UTF_8));
    }

    public static String answer(String resource, boolean authorized) {
        return "{\"entity_id\":\"" + ISSUER + "\",\"authority_id\":\"" + AUTHORITY + "\",\"action\":\"issue\",\"resource\":\"" + resource
                + "\",\"authorized\":" + authorized + ",\"time_evaluated\":\"2026-11-06T09:59:00Z\"}";
    }

    public static FetchResult problem404() {
        return new FetchResult(FetchResult.Outcome.NOT_FOUND, 404,
                "{\"type\":\"https://example.com/problems/not-found\",\"title\":\"not found\",\"status\":404,\"detail\":\"x\"}".getBytes(StandardCharsets.UTF_8), "HTTP_404");
    }
}
