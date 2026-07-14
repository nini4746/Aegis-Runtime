package com.aegis.jws;

import com.aegis.lifecycle.PolicyProperties;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * R9/R10 admission caps that live OUTSIDE the global {@link CostAwareScheduler} (D7/D8). The
 * global {@code Semaphore(8)} is the verified core and is never touched here.
 *
 * <ul>
 *   <li>R9: a per-algorithm in-flight counter. It is only consulted while the algorithm is
 *       THROTTLED; ACTIVE/RECOVERING never pay the cap. On saturation the caller rejects with
 *       503 and no global permit is consumed.</li>
 *   <li>R10: a small dedicated Semaphore isolating DEAD-fallback direct verification, so a flood
 *       of still-valid DEAD tokens cannot burn CPU without the global scheduler's protection.</li>
 * </ul>
 *
 * Every acquire is paired with a try/finally release on the hot path (D9, leak-safe).
 */
@Component
public class AdmissionGate {

    private final Map<String, AtomicInteger> inFlight = new ConcurrentHashMap<>();
    private final int throttleMaxConcurrent;
    private final int fallbackMaxConcurrent;
    private final Semaphore fallbackPool;

    public AdmissionGate(PolicyProperties policy) {
        this.throttleMaxConcurrent = policy.getThrottle().getMaxConcurrent();
        this.fallbackMaxConcurrent = policy.getFallback().getMaxConcurrent();
        this.fallbackPool = new Semaphore(this.fallbackMaxConcurrent);
    }

    private AtomicInteger counter(String algorithm) {
        return inFlight.computeIfAbsent(algorithm, k -> new AtomicInteger());
    }

    /**
     * THROTTLE cap (R9). Optimistically increments the algo in-flight counter; if that pushes it
     * past {@code throttle.max-concurrent} the increment is rolled back and {@code false} is
     * returned (the caller rejects, and the global scheduler is never consulted). On {@code true}
     * the caller MUST pair with {@link #exitThrottled} in a finally.
     */
    public boolean tryEnterThrottled(String algorithm) {
        AtomicInteger c = counter(algorithm);
        if (c.incrementAndGet() > throttleMaxConcurrent) {
            c.decrementAndGet();
            return false;
        }
        return true;
    }

    public void exitThrottled(String algorithm) {
        counter(algorithm).decrementAndGet();
    }

    /** Non-blocking acquire of a fallback-pool permit (R10/D8). Pair with {@link #releaseFallback}. */
    public boolean tryAcquireFallback() {
        return fallbackPool.tryAcquire();
    }

    public void releaseFallback() {
        fallbackPool.release();
    }

    // ---- observability / test seams ----
    public int inFlight(String algorithm) {
        AtomicInteger c = inFlight.get(algorithm);
        return c == null ? 0 : c.get();
    }

    public int fallbackAvailable() { return fallbackPool.availablePermits(); }

    public int throttleMaxConcurrent() { return throttleMaxConcurrent; }

    public int fallbackMaxConcurrent() { return fallbackMaxConcurrent; }
}
