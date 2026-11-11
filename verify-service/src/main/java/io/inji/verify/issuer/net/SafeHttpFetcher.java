package io.inji.verify.issuer.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpTimeoutException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Applies {@link UrlSafetyPolicy}, refuses redirects, caps response size and maps every failure to a
 * {@link FetchResult} so callers can distinguish "not there" from "could not reach".
 */
public final class SafeHttpFetcher implements HttpFetcher {

    private final UrlSafetyPolicy policy;
    private final HttpTransport transport;
    private final int maxBytes;
    private final Map<String, String> headers;

    public SafeHttpFetcher(UrlSafetyPolicy policy, HttpTransport transport, int maxBytes, Map<String, String> extraHeaders) {
        this.policy = policy;
        this.transport = transport;
        this.maxBytes = maxBytes;
        this.headers = new LinkedHashMap<>();
        this.headers.put("Accept", "application/json, application/did+json");
        if (extraHeaders != null) this.headers.putAll(extraHeaders);
    }

    @Override
    public FetchResult fetch(URI uri) {
        return execute(uri, false, () -> transport.get(uri, headers));
    }

    @Override
    public FetchResult post(URI uri, byte[] jsonBody) {
        Map<String, String> postHeaders = new LinkedHashMap<>(headers);
        postHeaders.put("Content-Type", "application/json");
        return execute(uri, true, () -> transport.post(uri, postHeaders, jsonBody));
    }

    private interface Call {
        HttpTransport.Response run() throws IOException, InterruptedException;
    }

    private FetchResult execute(URI uri, boolean keepNotFoundBody, Call call) {
        try {
            policy.check(uri);
        } catch (UnsafeUrlException e) {
            return FetchResult.of(FetchResult.Outcome.BLOCKED, e.reasonCode());
        }
        try (HttpTransport.Response r = call.run()) {
            int s = r.status();
            if (s == 404 || s == 410) {
                if (!keepNotFoundBody) return FetchResult.of(FetchResult.Outcome.NOT_FOUND, "HTTP_" + s);
                byte[] errBody = readBounded(r.body());
                return new FetchResult(FetchResult.Outcome.NOT_FOUND, s, errBody, "HTTP_" + s);
            }
            if (s >= 300 && s < 400) return FetchResult.of(FetchResult.Outcome.BLOCKED, "REDIRECT_NOT_FOLLOWED");
            if (s != 200) return FetchResult.of(FetchResult.Outcome.HTTP_ERROR, "HTTP_" + s);
            byte[] body = readBounded(r.body());
            if (body == null) return FetchResult.of(FetchResult.Outcome.TOO_LARGE, "RESPONSE_TOO_LARGE");
            return FetchResult.ok(s, body);
        } catch (HttpTimeoutException e) {
            return FetchResult.of(FetchResult.Outcome.TIMEOUT, "TIMEOUT");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return FetchResult.of(FetchResult.Outcome.NETWORK_ERROR, "INTERRUPTED");
        } catch (IOException e) {
            String name = e.getClass().getSimpleName();
            boolean timeout = name.contains("Timeout");
            return FetchResult.of(timeout ? FetchResult.Outcome.TIMEOUT : FetchResult.Outcome.NETWORK_ERROR, timeout ? "TIMEOUT" : "NETWORK_ERROR");
        } catch (RuntimeException e) {
            return FetchResult.of(FetchResult.Outcome.NETWORK_ERROR, "NETWORK_ERROR");
        }
    }

    /** @return bytes, or null if more than maxBytes were sent */
    private byte[] readBounded(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) {
            if (out.size() + n > maxBytes) return null;
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }
}
