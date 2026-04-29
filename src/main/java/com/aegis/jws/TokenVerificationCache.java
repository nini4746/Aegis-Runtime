package com.aegis.jws;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@Component
public class TokenVerificationCache {

    private final boolean enabled;
    private final int maxEntries;
    private final BoundedTokenMap cache;
    private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();
    private final AtomicLong lastSeenNowMs = new AtomicLong(0);

    private final Counter hits;
    private final Counter misses;
    private final Counter clockSkewEvictions;

    public TokenVerificationCache(MeterRegistry meters,
                                  @Value("${aegis.cache.enabled:true}") boolean enabled,
                                  @Value("${aegis.cache.max-entries:2048}") int maxEntries) {
        this.enabled = enabled;
        this.maxEntries = Math.max(16, maxEntries);
        this.cache = new BoundedTokenMap(this.maxEntries);
        this.hits = Counter.builder("aegis.cache.hits").register(meters);
        this.misses = Counter.builder("aegis.cache.misses").register(meters);
        this.clockSkewEvictions = Counter.builder("aegis.cache.clock_skew_evictions").register(meters);
    }

    public Jws<Claims> get(String token) {
        if (!enabled) return null;
        long now = monotonicNow();
        CachedJws e;
        rwLock.readLock().lock();
        try {
            e = cache.get(token);
        } finally {
            rwLock.readLock().unlock();
        }
        if (e == null || e.expiresAtMs <= now) {
            if (e != null) {
                rwLock.writeLock().lock();
                try {
                    cache.remove(token);
                } finally {
                    rwLock.writeLock().unlock();
                }
            }
            misses.increment();
            return null;
        }
        hits.increment();
        return e.jws;
    }

    public void put(String token, Jws<Claims> jws) {
        if (!enabled) return;
        long expiresAt = jws.getPayload().getExpiration() == null
                ? monotonicNow() + 60_000
                : jws.getPayload().getExpiration().getTime();
        rwLock.writeLock().lock();
        try {
            cache.put(token, new CachedJws(jws, expiresAt));
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    public int size() {
        rwLock.readLock().lock();
        try {
            return cache.size();
        } finally {
            rwLock.readLock().unlock();
        }
    }

    // monotonic clock guard: never return a value smaller than previously observed.
    // protects against backward NTP adjustments accepting expired tokens.
    private long monotonicNow() {
        long sysNow = System.currentTimeMillis();
        while (true) {
            long prev = lastSeenNowMs.get();
            if (sysNow >= prev) {
                if (lastSeenNowMs.compareAndSet(prev, sysNow)) return sysNow;
            } else {
                clockSkewEvictions.increment();
                return prev;
            }
        }
    }

    private record CachedJws(Jws<Claims> jws, long expiresAtMs) {}

    private static final class BoundedTokenMap extends LinkedHashMap<String, CachedJws> {
        private final int max;

        BoundedTokenMap(int max) {
            super(64, 0.75f, true);
            this.max = max;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, CachedJws> eldest) {
            return size() > max;
        }
    }
}
