package io.inji.verify.issuer.net;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * java.net.http transport: no redirects, HTTP/1.1, strict connect and request timeouts.
 * TLS certificate chain and hostname verification use the JVM defaults and are never relaxed here.
 */
public final class JdkHttpTransport implements HttpTransport {

    private final HttpClient client;
    private final Duration requestTimeout;

    public JdkHttpTransport(Duration connectTimeout, Duration requestTimeout) {
        this.requestTimeout = requestTimeout;
        this.client = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    @Override
    public Response get(URI uri, Map<String, String> headers) throws IOException, InterruptedException {
        HttpRequest.Builder rb = HttpRequest.newBuilder(uri).timeout(requestTimeout).GET();
        headers.forEach(rb::header);
        HttpResponse<InputStream> r = client.send(rb.build(), HttpResponse.BodyHandlers.ofInputStream());
        return new Response() {
            @Override
            public int status() {
                return r.statusCode();
            }

            @Override
            public InputStream body() {
                return r.body();
            }

            @Override
            public void close() {
                try {
                    r.body().close();
                } catch (IOException ignored) {
                    // nothing to do
                }
            }
        };
    }
}
