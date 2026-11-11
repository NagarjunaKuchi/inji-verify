package io.inji.verify.issuer.net;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class SafeHttpFetcherPostTest {

    static final URI URL = URI.create("https://registry.example.org/authorization");

    static final class Transport implements HttpTransport {
        final int status;
        final byte[] body;
        Map<String, String> postHeaders;
        byte[] postBody;
        boolean called;
        boolean throwTimeout;

        Transport(int status, String body) {
            this.status = status;
            this.body = body.getBytes();
        }

        @Override
        public Response get(URI uri, Map<String, String> headers) {
            throw new AssertionError("GET not expected");
        }

        @Override
        public Response post(URI uri, Map<String, String> headers, byte[] b) throws java.io.IOException {
            called = true;
            postHeaders = headers;
            postBody = b;
            if (throwTimeout) throw new java.net.http.HttpTimeoutException("slow");
            return new Response() {
                public int status() {
                    return status;
                }

                public InputStream body() {
                    return new ByteArrayInputStream(body);
                }

                public void close() {
                }
            };
        }
    }

    private static UrlSafetyPolicy allowAll() {
        return new UrlSafetyPolicy(Set.of(443), Set.of(), false, h -> new java.net.InetAddress[]{java.net.InetAddress.getByAddress(new byte[]{93, (byte) 184, (byte) 216, 34})});
    }

    @Test
    void postsJsonWithExtraHeadersAndReturnsBody() {
        Transport t = new Transport(200, "{\"authorized\":true}");
        FetchResult r = new SafeHttpFetcher(allowAll(), t, 100, Map.of("Authorization", "Bearer t")).post(URL, "{\"a\":1}".getBytes());
        assertTrue(r.isOk());
        assertEquals("application/json", t.postHeaders.get("Content-Type"));
        assertEquals("Bearer t", t.postHeaders.get("Authorization"));
        assertEquals("{\"a\":1}", new String(t.postBody));
    }

    @Test
    void notFoundKeepsItsBodyOnPostOnly() {
        Transport t = new Transport(404, "{\"type\":\"x\",\"title\":\"y\"}");
        FetchResult r = new SafeHttpFetcher(allowAll(), t, 100, Map.of()).post(URL, new byte[0]);
        assertEquals(FetchResult.Outcome.NOT_FOUND, r.outcome());
        assertEquals(404, r.status());
        assertEquals("{\"type\":\"x\",\"title\":\"y\"}", new String(r.body()));
    }

    @Test
    void unsafeUrlNeverReachesTransport() {
        Transport t = new Transport(200, "{}");
        FetchResult r = new SafeHttpFetcher(allowAll(), t, 100, Map.of()).post(URI.create("http://registry.example.org/authorization"), new byte[0]);
        assertEquals(FetchResult.Outcome.BLOCKED, r.outcome());
        assertFalse(t.called);
    }

    @Test
    void redirectsErrorsTimeoutsAndOversizeAreClassified() {
        assertEquals(FetchResult.Outcome.BLOCKED, new SafeHttpFetcher(allowAll(), new Transport(302, ""), 100, Map.of()).post(URL, new byte[0]).outcome());
        assertEquals(FetchResult.Outcome.HTTP_ERROR, new SafeHttpFetcher(allowAll(), new Transport(401, ""), 100, Map.of()).post(URL, new byte[0]).outcome());
        assertEquals(FetchResult.Outcome.HTTP_ERROR, new SafeHttpFetcher(allowAll(), new Transport(500, ""), 100, Map.of()).post(URL, new byte[0]).outcome());
        assertEquals(FetchResult.Outcome.TOO_LARGE, new SafeHttpFetcher(allowAll(), new Transport(200, "x".repeat(200)), 100, Map.of()).post(URL, new byte[0]).outcome());
        Transport slow = new Transport(200, "");
        slow.throwTimeout = true;
        assertEquals(FetchResult.Outcome.TIMEOUT, new SafeHttpFetcher(allowAll(), slow, 100, Map.of()).post(URL, new byte[0]).outcome());
    }

    @Test
    void getOnlyTransportsAndFetchersFailSafely() {
        HttpTransport getOnly = (uri, headers) -> {
            throw new AssertionError();
        };
        FetchResult r = new SafeHttpFetcher(allowAll(), getOnly, 100, Map.of()).post(URL, new byte[0]);
        assertEquals(FetchResult.Outcome.NETWORK_ERROR, r.outcome(), "UnsupportedOperationException is contained");

        HttpFetcher plain = uri -> FetchResult.ok(200, new byte[0]);
        assertEquals(FetchResult.Outcome.HTTP_ERROR, plain.post(URL, new byte[0]).outcome());
    }
}
