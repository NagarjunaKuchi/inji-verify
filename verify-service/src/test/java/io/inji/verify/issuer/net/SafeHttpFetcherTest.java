package io.inji.verify.issuer.net;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpTimeoutException;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SafeHttpFetcherTest {

    private static HttpTransport transport(int status, byte[] body) {
        return (uri, headers) -> new HttpTransport.Response() {
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

    private static UrlSafetyPolicy allowAll() {
        return new UrlSafetyPolicy(Set.of(443), Set.of(), false, h -> new java.net.InetAddress[]{java.net.InetAddress.getByAddress(new byte[]{93, (byte) 184, (byte) 216, 34})});
    }

    private static final URI URL = URI.create("https://issuer.example.org/.well-known/did.json");

    @Test
    void returnsBodyOnSuccess() {
        FetchResult r = new SafeHttpFetcher(allowAll(), transport(200, "{}".getBytes()), 100, Map.of()).fetch(URL);
        assertEquals(FetchResult.Outcome.OK, r.outcome());
        assertEquals(2, r.body().length);
    }

    @Test
    void mapsNotFoundAndServerErrorsDifferently() {
        assertEquals(FetchResult.Outcome.NOT_FOUND, new SafeHttpFetcher(allowAll(), transport(404, new byte[0]), 100, Map.of()).fetch(URL).outcome());
        assertEquals(FetchResult.Outcome.HTTP_ERROR, new SafeHttpFetcher(allowAll(), transport(503, new byte[0]), 100, Map.of()).fetch(URL).outcome());
        assertEquals(FetchResult.Outcome.HTTP_ERROR, new SafeHttpFetcher(allowAll(), transport(500, new byte[0]), 100, Map.of()).fetch(URL).outcome());
    }

    @Test
    void neverFollowsRedirects() {
        FetchResult r = new SafeHttpFetcher(allowAll(), transport(302, new byte[0]), 100, Map.of()).fetch(URL);
        assertEquals(FetchResult.Outcome.BLOCKED, r.outcome());
        assertEquals("REDIRECT_NOT_FOLLOWED", r.detail());
    }

    @Test
    void rejectsOversizedResponses() {
        FetchResult r = new SafeHttpFetcher(allowAll(), transport(200, new byte[101]), 100, Map.of()).fetch(URL);
        assertEquals(FetchResult.Outcome.TOO_LARGE, r.outcome());
    }

    @Test
    void blockedUrlNeverReachesTransport() {
        boolean[] called = {false};
        HttpTransport spy = (uri, h) -> {
            called[0] = true;
            throw new IOException();
        };
        FetchResult r = new SafeHttpFetcher(allowAll(), spy, 100, Map.of()).fetch(URI.create("https://169.254.169.254/latest/meta-data"));
        assertEquals(FetchResult.Outcome.BLOCKED, r.outcome());
        assertFalse(called[0]);
    }

    @Test
    void timeoutsAndNetworkErrorsAreDistinctFromBlocked() {
        HttpTransport timeout = (u, h) -> {
            throw new HttpTimeoutException("slow");
        };
        HttpTransport broken = (u, h) -> {
            throw new IOException("connection reset: 10.0.0.1:443 secret detail");
        };
        assertEquals(FetchResult.Outcome.TIMEOUT, new SafeHttpFetcher(allowAll(), timeout, 100, Map.of()).fetch(URL).outcome());
        FetchResult net = new SafeHttpFetcher(allowAll(), broken, 100, Map.of()).fetch(URL);
        assertEquals(FetchResult.Outcome.NETWORK_ERROR, net.outcome());
        assertFalse(net.detail().contains("10.0.0.1"), "internal detail must not leak");
    }
}
