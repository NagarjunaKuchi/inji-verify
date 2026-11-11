package io.inji.verify.issuer.metadata;

import io.inji.verify.issuer.registry.IssuerTrustRegistry;
import io.inji.verify.issuer.registry.RegistryLookup;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

/**
 * Retrieves canonical issuer metadata from the configured registries (first hit wins), with caching and
 * staleness protection.
 * <ul>
 *   <li>Found / NotFound are cached for their own TTLs; Unavailable is never cached.</li>
 *   <li>Metadata whose {@code asOf} is older than {@code maxMetadataAge} is treated as unavailable
 *       (stale data must not be used to vouch for an issuer).</li>
 *   <li>If any registry was unavailable and none had the issuer, the answer is Unavailable, not NotFound.</li>
 * </ul>
 */
public class IssuerMetadataService {

    private final List<IssuerTrustRegistry> registries;
    private final TtlCache<String, RegistryLookup> cache;
    private final Duration foundTtl;
    private final Duration notFoundTtl;
    private final Duration maxMetadataAge;
    private final Clock clock;

    public IssuerMetadataService(List<IssuerTrustRegistry> registries, TtlCache<String, RegistryLookup> cache,
                                 Duration foundTtl, Duration notFoundTtl, Duration maxMetadataAge, Clock clock) {
        this.registries = List.copyOf(registries);
        this.cache = cache;
        this.foundTtl = foundTtl;
        this.notFoundTtl = notFoundTtl;
        this.maxMetadataAge = maxMetadataAge;
        this.clock = clock;
    }

    public boolean isRegistryConfigured() {
        return !registries.isEmpty();
    }

    public RegistryLookup lookup(String issuerId) {
        return lookup(issuerId, List.of());
    }

    /**
     * @param credentialTypes types declared by the credential; only used by registries that are credential-type aware.
     *                        The cache key includes them only when such a registry is configured.
     */
    public RegistryLookup lookup(String issuerId, java.util.Collection<String> credentialTypes) {
        if (registries.isEmpty()) return new RegistryLookup.Unavailable(null, "REGISTRY_NOT_CONFIGURED");
        String key = cacheKey(issuerId, credentialTypes);
        var hit = cache.get(key);
        if (hit.isPresent()) return hit.get();

        RegistryLookup unavailable = null;
        String notFoundBy = null;
        for (IssuerTrustRegistry registry : registries) {
            RegistryLookup r;
            try {
                r = registry.lookup(issuerId, credentialTypes);
            } catch (RuntimeException e) {
                r = new RegistryLookup.Unavailable(registry.registryId(), "REGISTRY_UNAVAILABLE");
            }
            if (r instanceof RegistryLookup.Found f) {
                if (isStale(f)) {
                    unavailable = new RegistryLookup.Unavailable(f.registryId(), "STALE_REGISTRY_METADATA");
                    continue;
                }
                cache.put(key, f, foundTtl);
                return f;
            } else if (r instanceof RegistryLookup.NotFound nf) {
                if (notFoundBy == null) notFoundBy = nf.registryId();
            } else if (r instanceof RegistryLookup.Unavailable u) {
                unavailable = u;
            }
        }
        if (unavailable != null) return unavailable;
        RegistryLookup nf = new RegistryLookup.NotFound(notFoundBy);
        cache.put(key, nf, notFoundTtl);
        return nf;
    }

    /** Drops the type-independent entry for the issuer. With type-aware registries use {@link #invalidateAll()}. */
    public void invalidate(String issuerId) {
        cache.invalidate(issuerId);
    }

    public void invalidateAll() {
        cache.clear();
    }

    private String cacheKey(String issuerId, java.util.Collection<String> credentialTypes) {
        if (credentialTypes == null || credentialTypes.isEmpty() || registries.stream().noneMatch(IssuerTrustRegistry::credentialTypeAware)) {
            return issuerId;
        }
        return issuerId + "|" + String.join(",", new java.util.TreeSet<>(credentialTypes));
    }

    private boolean isStale(RegistryLookup.Found f) {
        var asOf = f.metadata().asOf();
        if (asOf == null || maxMetadataAge == null || maxMetadataAge.isZero()) return false;
        return asOf.plus(maxMetadataAge).isBefore(clock.instant());
    }
}
