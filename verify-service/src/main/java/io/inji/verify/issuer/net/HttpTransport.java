package io.inji.verify.issuer.net;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

/** Minimal HTTP seam so SSRF/size/timeout logic can be tested without a network. */
public interface HttpTransport {

    /** Response whose body stream is bounded by the caller. */
    interface Response extends AutoCloseable {
        int status();

        java.io.InputStream body() throws IOException;

        @Override
        void close();
    }

    /** Must NOT follow redirects. Must apply connect + total request timeouts. */
    Response get(URI uri, Map<String, String> headers) throws IOException, InterruptedException;

    /** Same guarantees as {@link #get}. Optional: transports that only support GET need not override it. */
    default Response post(URI uri, Map<String, String> headers, byte[] body) throws IOException, InterruptedException {
        throw new UnsupportedOperationException("POST not supported by this transport");
    }
}
