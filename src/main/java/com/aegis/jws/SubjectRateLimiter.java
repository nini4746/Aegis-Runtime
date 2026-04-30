package com.aegis.jws;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Per-subject token bucket. Each subject has its own bucket independently of the
 * cost-aware scheduler, which protects the verifier as a whole. This guards a
 * single misbehaving credential from monopolising verification capacity.
 *
 * Bucket is computed lazily on each check: stored {@code tokens} + delta based
 * on monotonic time since last refill. No background sweeper needed; idle
 * subjects drop out of the map only when explicitly evicted (max-size bound).
 */
@Component
public class SubjectRateLimiter {

    private final boolean enabled;
    private final int capacity;
    private final double refillPerSec;
    private final int maxTrackedSubjects;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    private final Counter allowed;
    private final Counter rejected;

    public SubjectRateLimiter(MeterRegistry meters,
                              @Value("${aegis.ratelimit.enabled:true}") boolean enabled,
                              @Value("${aegis.ratelimit.capacity:30}") int capacity,
                              @Value("${aegis.ratelimit.refill-per-sec:10.0}") double refillPerSec,
                              @Value("${aegis.ratelimit.max-subjects:10000}") int maxTrackedSubjects) {
        this.enabled = enabled;
        this.capacity = Math.max(1, capacity);
        this.refillPerSec = Math.max(0.1, refillPerSec);
        this.maxTrackedSubjects = Math.max(64, maxTrackedSubjects);
        this.allowed = Counter.builder("aegis.ratelimit.allowed").register(meters);
        this.rejected = Counter.builder("aegis.ratelimit.rejected").register(meters);
        meters.gauge("aegis.ratelimit.tracked", buckets, Map::size);
    }

    /**
     * Try to consume one token for this subject. Returns true if allowed.
     */
    public boolean tryAcquire(String subject) {
        if (!enabled || subject == null || subject.isBlank()) {
            allowed.increment();
            return true;
        }
        // simple eviction: bound the map; on overflow, clear (rare under steady state)
        if (buckets.size() > maxTrackedSubjects) {
            buckets.clear();
        }
        Bucket b = buckets.computeIfAbsent(subject, k -> new Bucket(capacity, System.nanoTime()));
        boolean ok = b.tryAcquire(capacity, refillPerSec);
        if (ok) allowed.increment();
        else rejected.increment();
        return ok;
    }

    public int trackedSubjects() {
        return buckets.size();
    }

    public void reset() {
        buckets.clear();
    }

    private static final class Bucket {
        // store tokens scaled by 1_000_000 so integer atomics work without doubles
        private final AtomicLong scaledTokens;
        private final AtomicLong lastRefillNanos;

        Bucket(int capacity, long now) {
            this.scaledTokens = new AtomicLong(capacity * 1_000_000L);
            this.lastRefillNanos = new AtomicLong(now);
        }

        boolean tryAcquire(int capacity, double refillPerSec) {
            long now = System.nanoTime();
            while (true) {
                long prevTokens = scaledTokens.get();
                long prevRefill = lastRefillNanos.get();
                long deltaNanos = Math.max(0L, now - prevRefill);
                double addedTokens = (deltaNanos / 1_000_000_000.0) * refillPerSec;
                long addedScaled = (long) (addedTokens * 1_000_000L);
                long capScaled = capacity * 1_000_000L;
                long updated = Math.min(capScaled, prevTokens + addedScaled);
                if (updated < 1_000_000L) {
                    // not enough tokens; still update timestamp so we don't busy-burn refill
                    lastRefillNanos.compareAndSet(prevRefill, now);
                    scaledTokens.compareAndSet(prevTokens, updated);
                    return false;
                }
                long after = updated - 1_000_000L;
                if (scaledTokens.compareAndSet(prevTokens, after)) {
                    lastRefillNanos.compareAndSet(prevRefill, now);
                    return true;
                }
                // CAS failure -> retry
            }
        }
    }
}
