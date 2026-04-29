package com.aegis.jws;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class TokenVerificationCache {

    private final boolean enabled;
    private final int maxEntries;
    private final BoundedTokenMap cache;
    private final Counter hits;
    private final Counter misses;

    public TokenVerificationCache(MeterRegistry meters,
                                  @Value("${aegis.cache.enabled:true}") boolean enabled,
                                  @Value("${aegis.cache.max-entries:2048}") int maxEntries) {
        this.enabled = enabled;
        this.maxEntries = Math.max(16, maxEntries);
        this.cache = new BoundedTokenMap(this.maxEntries);
        this.hits = Counter.builder("aegis.cache.hits").register(meters);
        this.misses = Counter.builder("aegis.cache.misses").register(meters);
    }

    public Jws<Claims> get(String token) {
        if (!enabled) return null;
        long now = System.currentTimeMillis();
        CachedJws e;
        synchronized (cache) {
            e = cache.get(token);
            if (e != null && e.expiresAtMs <= now) {
                cache.remove(token);
                e = null;
            }
        }
        if (e != null) {
            hits.increment();
            return e.jws;
        }
        misses.increment();
        return null;
    }

    public void put(String token, Jws<Claims> jws) {
        if (!enabled) return;
        long expiresAt = jws.getPayload().getExpiration() == null
                ? System.currentTimeMillis() + 60_000
                : jws.getPayload().getExpiration().getTime();
        synchronized (cache) {
            cache.put(token, new CachedJws(jws, expiresAt));
        }
    }

    public int size() {
        synchronized (cache) {
            return cache.size();
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
