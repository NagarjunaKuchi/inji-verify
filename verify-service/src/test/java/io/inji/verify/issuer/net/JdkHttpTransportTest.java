package io.inji.verify.issuer.net;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Exercises the real JDK transport against a local plain-HTTP server (the https-only rule lives in UrlSafetyPolicy). */
class JdkHttpTransportTest {

    private HttpServer server() throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        s.createContext("/ok", ex -> {
            byte[] b = "{\"a\":1}".getBytes();
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        s.createContext("/redirect", ex -> {
            ex.getResponseHeaders().add("Location", "/ok");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        s.createContext("/slow", ex -> {
            try {
                Thread.sleep(1500);
            } catch (InterruptedException ignored) {
            }
            ex.sendResponseHeaders(200, -1);
            ex.close();
        });
        s.start();
        return s;
    }

    @Test
    void readsResponseDoesNotFollowRedirectsAndHonoursTimeout() throws Exception {
        HttpServer s = server();
        try {
            String base = "http://127.0.0.1:" + s.getAddress().getPort();
            JdkHttpTransport t = new JdkHttpTransport(Duration.ofSeconds(1), Duration.ofMillis(300));
            try (HttpTransport.Response r = t.get(URI.create(base + "/ok"), Map.of("Accept", "application/json"))) {
                assertEquals(200, r.status());
                assertEquals("{\"a\":1}", new String(r.body().readAllBytes()));
            }
            try (HttpTransport.Response r = t.get(URI.create(base + "/redirect"), Map.of())) {
                assertEquals(302, r.status());
            }
            assertThrows(java.net.http.HttpTimeoutException.class, () -> t.get(URI.create(base + "/slow"), Map.of()));
        } finally {
            s.stop(0);
        }
    }
}
