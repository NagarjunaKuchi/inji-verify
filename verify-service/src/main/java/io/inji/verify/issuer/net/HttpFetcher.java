package io.inji.verify.issuer.net;

import java.net.URI;

public interface HttpFetcher {
    FetchResult fetch(URI uri);
}
