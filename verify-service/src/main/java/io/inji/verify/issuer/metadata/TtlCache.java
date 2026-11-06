package io.inji.verify.issuer.metadata;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** Small thread-safe LRU cache with per-entry TTL. Entries are evicted lazily and by size. */
public final class TtlCache<K, V> {

    private record Entry<V>(V value, Instant expiresAt) {
    }

    private final Map<K, Entry<V>> map;
    private final Clock clock;
    private final int maxEntries;

    public TtlCache(int maxEntries, Clock clock) {
        this.maxEntries = Math.max(1, maxEntries);
        this.clock = clock;
        this.map = new LinkedHashMap<>(16, 0.75f, true);
    }

    public synchronized Optional<V> get(K key) {
        Entry<V> e = map.get(key);
        if (e == null) return Optional.empty();
        if (!clock.instant().isBefore(e.expiresAt())) {
            map.remove(key);
            return Optional.empty();
        }
        return Optional.of(e.value());
    }

    public synchronized void put(K key, V value, Duration ttl) {
        if (ttl == null || ttl.isZero() || ttl.isNegative()) return;
        map.put(key, new Entry<>(value, clock.instant().plus(ttl)));
        while (map.size() > maxEntries) {
            K eldest = map.keySet().iterator().next();
            map.remove(eldest);
        }
    }

    public synchronized void invalidate(K key) {
        map.remove(key);
    }

    public synchronized void clear() {
        map.clear();
    }

    public synchronized int size() {
        return map.size();
    }
}
