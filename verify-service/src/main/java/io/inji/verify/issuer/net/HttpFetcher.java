package io.inji.verify.issuer.net;

import java.net.URI;

public interface HttpFetcher {
    FetchResult fetch(URI uri);

    /**
     * POST a JSON body. Unlike {@link #fetch}, a 404 keeps its body (outcome NOT_FOUND, status 404) so callers
     * can tell a registry's "unknown" answer from a wrong URL. Fetchers that cannot POST report HTTP_ERROR.
     */
    default FetchResult post(URI uri, byte[] jsonBody) {
        return FetchResult.of(FetchResult.Outcome.HTTP_ERROR, "POST_NOT_SUPPORTED");
    }
}
