package io.inji.verify.issuer.did;

import io.inji.verify.issuer.identifier.IssuerIdentifier;
import io.inji.verify.issuer.metadata.TtlCache;

import java.time.Duration;

/** Caches only successful resolutions. Failures are never cached so a transient outage heals immediately. */
public final class CachingDidResolver implements DidResolver {

    private final DidResolver delegate;
    private final TtlCache<String, DidResolution> cache;
    private final Duration ttl;

    public CachingDidResolver(DidResolver delegate, TtlCache<String, DidResolution> cache, Duration ttl) {
        this.delegate = delegate;
        this.cache = cache;
        this.ttl = ttl;
    }

    @Override
    public IssuerIdentifier.Type supportedType() {
        return delegate.supportedType();
    }

    @Override
    public DidResolution resolve(String did) {
        var hit = cache.get(did);
        if (hit.isPresent()) return hit.get();
        DidResolution r = delegate.resolve(did);
        if (r instanceof DidResolution.Resolved) cache.put(did, r, ttl);
        return r;
    }

    public void invalidate(String did) {
        cache.invalidate(did);
    }
}
