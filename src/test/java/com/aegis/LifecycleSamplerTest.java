package com.aegis;

import com.aegis.jws.TokenVerificationCache;
import com.aegis.lifecycle.AlgorithmMetricSource;
import com.aegis.lifecycle.AlgorithmState;
import com.aegis.lifecycle.KillReason;
import com.aegis.lifecycle.LifecycleActuator;
import com.aegis.lifecycle.LifecycleRegistry;
import com.aegis.lifecycle.LifecycleSampler;
import com.aegis.lifecycle.PolicyEngine;
import com.aegis.lifecycle.PolicyProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Sampler + state machine with a FAKE clock and hand-fed metric snapshots (R3/R8).
 * No real sleep; dwell/cooldown timing is asserted exactly.
 */
class LifecycleSamplerTest {

    /** Controllable metric source. */
    static class FakeMetrics implements AlgorithmMetricSource {
        final Map<String, Double> avg = new HashMap<>();
        final Map<String, Double> fail = new HashMap<>();
        double memoryPressure = 0.0;
        public double avgVerifyMs(String a) { return avg.getOrDefault(a, 1.0); }
        public double failureRate(String a) { return fail.getOrDefault(a, 0.0); }
        public double memoryPressure() { return memoryPressure; }
    }

    /** Cache that records per-algorithm invalidation without needing a real signed JWS. */
    static class RecordingCache extends TokenVerificationCache {
        String invalidated;
        RecordingCache() { super(new SimpleMeterRegistry(), true, 64); }
        @Override public int invalidateAlgorithm(String algorithm) { this.invalidated = algorithm; return 0; }
    }

    private long ms(long v) { return v * 1_000_000L; }

    @Test
    void full_lifecycle_active_throttled_dead_recovering_active_with_fake_clock() {
        AtomicLong clock = new AtomicLong(0);
        LifecycleRegistry registry = new LifecycleRegistry(clock::get);
        FakeMetrics metrics = new FakeMetrics();
        RecordingCache cache = new RecordingCache();
        PolicyProperties cfg = new PolicyProperties();
        LifecycleActuator actuator = new LifecycleActuator(registry, cache);
        LifecycleSampler sampler = new LifecycleSampler(registry, metrics, new PolicyEngine(), cfg, actuator, clock::get);

        // RS256 is killable (not min-share). Drive it unhealthy under memory pressure.
        metrics.avg.put("RS256", 100.0);
        metrics.fail.put("RS256", 0.5);
        metrics.memoryPressure = 0.9;

        // t=0: ACTIVE -> THROTTLED
        sampler.tick();
        assertEquals(AlgorithmState.THROTTLED, registry.stateOf("RS256"));

        // just before dwell: no kill
        clock.set(ms(cfg.getDeadDwellMs() - 1));
        sampler.tick();
        assertEquals(AlgorithmState.THROTTLED, registry.stateOf("RS256"));
        assertNull(cache.invalidated, "must not kill before dwell elapses");

        // exactly at dwell: THROTTLED -> DEAD, cache invalidated, reason preserved
        clock.set(ms(cfg.getDeadDwellMs()));
        sampler.tick();
        assertEquals(AlgorithmState.DEAD, registry.stateOf("RS256"));
        assertEquals("RS256", cache.invalidated, "kill invalidates that algorithm's cache");
        assertEquals(KillReason.MEMORY_PRESSURE, registry.lifecycle("RS256").lastKillReason());

        // before cooldown: stays DEAD
        clock.set(ms(cfg.getDeadDwellMs()) + ms(cfg.getRecoverCooldownMs() - 1));
        sampler.tick();
        assertEquals(AlgorithmState.DEAD, registry.stateOf("RS256"));

        // cooldown elapsed: DEAD -> RECOVERING
        clock.set(ms(cfg.getDeadDwellMs()) + ms(cfg.getRecoverCooldownMs()));
        sampler.tick();
        assertEquals(AlgorithmState.RECOVERING, registry.stateOf("RS256"));

        // metrics recover: RECOVERING -> ACTIVE
        metrics.avg.put("RS256", 2.0);
        metrics.fail.put("RS256", 0.0);
        sampler.tick();
        assertEquals(AlgorithmState.ACTIVE, registry.stateOf("RS256"));
    }

    @Test
    void min_share_algorithm_throttles_but_never_dies() {
        AtomicLong clock = new AtomicLong(0);
        LifecycleRegistry registry = new LifecycleRegistry(clock::get);
        FakeMetrics metrics = new FakeMetrics();
        PolicyProperties cfg = new PolicyProperties();
        LifecycleActuator actuator = new LifecycleActuator(registry, new RecordingCache());
        LifecycleSampler sampler = new LifecycleSampler(registry, metrics, new PolicyEngine(), cfg, actuator, clock::get);

        metrics.avg.put("HS256", 100.0);
        metrics.fail.put("HS256", 0.9);
        metrics.memoryPressure = 0.99;

        sampler.tick();
        assertEquals(AlgorithmState.THROTTLED, registry.stateOf("HS256"));

        clock.set(ms(cfg.getDeadDwellMs() * 10)); // long past dwell
        sampler.tick();
        assertEquals(AlgorithmState.THROTTLED, registry.stateOf("HS256"), "min-share must never reach DEAD");
    }
}
