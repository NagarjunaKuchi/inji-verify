package io.inji.verify.issuer.did;

import io.inji.verify.issuer.identifier.IssuerIdentifier;
import io.inji.verify.issuer.net.FetchResult;
import io.inji.verify.issuer.net.HttpFetcher;

import java.net.URI;

public final class DidWebResolver implements DidResolver {

    private final HttpFetcher fetcher;
    private final DidDocumentParser parser;

    public DidWebResolver(HttpFetcher fetcher, DidDocumentParser parser) {
        this.fetcher = fetcher;
        this.parser = parser;
    }

    @Override
    public IssuerIdentifier.Type supportedType() {
        return IssuerIdentifier.Type.DID_WEB;
    }

    @Override
    public DidResolution resolve(String did) {
        URI uri;
        try {
            uri = DidWebUrls.toUri(did);
        } catch (IllegalArgumentException e) {
            return new DidResolution.Malformed(e.getMessage());
        }
        FetchResult r = fetcher.fetch(uri);
        return switch (r.outcome()) {
            case OK -> {
                try {
                    yield new DidResolution.Resolved(parser.parse(r.body(), did));
                } catch (MalformedDidDocumentException e) {
                    yield new DidResolution.Malformed(e.reasonCode());
                }
            }
            case NOT_FOUND -> new DidResolution.NotFound();
            case BLOCKED -> new DidResolution.Blocked(r.detail());
            case TOO_LARGE -> new DidResolution.Malformed("DID_DOCUMENT_TOO_LARGE");
            case TIMEOUT -> new DidResolution.Unavailable("DID_RESOLUTION_TIMEOUT");
            case HTTP_ERROR, NETWORK_ERROR -> new DidResolution.Unavailable("DID_RESOLUTION_UNAVAILABLE");
        };
    }
}
