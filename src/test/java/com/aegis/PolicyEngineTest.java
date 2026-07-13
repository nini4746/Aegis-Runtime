package com.aegis;

import com.aegis.lifecycle.AlgoSample;
import com.aegis.lifecycle.AlgorithmState;
import com.aegis.lifecycle.KillReason;
import com.aegis.lifecycle.PolicyEngine;
import com.aegis.lifecycle.PolicyProperties;
import com.aegis.lifecycle.PolicySnapshot;
import com.aegis.lifecycle.Transition;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Pure decision-function tests (R2/R8): no clock, no Spring, deterministic. */
class PolicyEngineTest {

    private final PolicyEngine engine = new PolicyEngine();
    private final PolicyProperties cfg = new PolicyProperties(); // D1/D2 defaults

    private long msToNanos(long ms) { return ms * 1_000_000L; }

    private PolicySnapshot snap(double memoryPressure, AlgoSample... samples) {
        Map<String, AlgoSample> m = new LinkedHashMap<>();
        for (AlgoSample s : samples) m.put(s.algorithm(), s);
        return new PolicySnapshot(m, memoryPressure);
    }

    @Test
    void active_to_throttled_via_latency() {
        var s = new AlgoSample("RS256", AlgorithmState.ACTIVE, 60.0, 0.0, 0);
        List<Transition> ts = engine.decide(snap(0.1, s), cfg);
        assertEquals(1, ts.size());
        assertEquals(AlgorithmState.THROTTLED, ts.get(0).to());
    }

    @Test
    void active_to_throttled_via_failure_rate() {
        var s = new AlgoSample("RS256", AlgorithmState.ACTIVE, 1.0, 0.9, 0);
        List<Transition> ts = engine.decide(snap(0.1, s), cfg);
        assertEquals(1, ts.size());
        assertEquals(AlgorithmState.THROTTLED, ts.get(0).to());
    }

    @Test
    void active_stays_when_healthy() {
        var s = new AlgoSample("RS256", AlgorithmState.ACTIVE, 10.0, 0.0, 0);
        assertTrue(engine.decide(snap(0.99, s), cfg).isEmpty());
    }

    @Test
    void throttled_to_dead_honours_kill_order_one_per_tick() {
        long dwell = msToNanos(cfg.getDeadDwellMs());
        var rs = new AlgoSample("RS256", AlgorithmState.THROTTLED, 100.0, 0.5, dwell);
        var es = new AlgoSample("ES256", AlgorithmState.THROTTLED, 100.0, 0.5, dwell);
        // default kill-order is [ES256, RS256] -> ES256 killed first, and only one per tick
        List<Transition> ts = engine.decide(snap(0.9, rs, es), cfg);
        List<Transition> kills = ts.stream().filter(t -> t.to() == AlgorithmState.DEAD).toList();
        assertEquals(1, kills.size(), "at most one kill per tick");
        assertEquals("ES256", kills.get(0).algorithm());
        assertEquals(KillReason.MEMORY_PRESSURE, kills.get(0).reason());
    }

    @Test
    void min_share_algorithm_is_never_killed() {
        long dwell = msToNanos(cfg.getDeadDwellMs());
        var hs = new AlgoSample("HS256", AlgorithmState.THROTTLED, 100.0, 0.9, dwell);
        List<Transition> ts = engine.decide(snap(0.99, hs), cfg);
        assertTrue(ts.stream().noneMatch(t -> t.to() == AlgorithmState.DEAD),
                "HS256 (min-share) must not be killed");
    }

    @Test
    void throttled_not_killed_before_dwell_or_without_pressure() {
        long shortDwell = msToNanos(cfg.getDeadDwellMs() - 1);
        var early = new AlgoSample("RS256", AlgorithmState.THROTTLED, 100.0, 0.5, shortDwell);
        assertTrue(engine.decide(snap(0.99, early), cfg).stream()
                .noneMatch(t -> t.to() == AlgorithmState.DEAD), "dwell not reached");

        long dwell = msToNanos(cfg.getDeadDwellMs());
        var lowMem = new AlgoSample("RS256", AlgorithmState.THROTTLED, 100.0, 0.5, dwell);
        assertTrue(engine.decide(snap(0.5, lowMem), cfg).stream()
                .noneMatch(t -> t.to() == AlgorithmState.DEAD), "memory pressure too low");
    }

    @Test
    void throttled_to_active_when_metrics_recover() {
        var s = new AlgoSample("RS256", AlgorithmState.THROTTLED, 5.0, 0.0, msToNanos(9999));
        List<Transition> ts = engine.decide(snap(0.99, s), cfg);
        assertEquals(1, ts.size());
        assertEquals(AlgorithmState.ACTIVE, ts.get(0).to());
    }

    @Test
    void dead_to_recovering_after_cooldown() {
        var s = new AlgoSample("RS256", AlgorithmState.DEAD, 100.0, 0.5, msToNanos(cfg.getRecoverCooldownMs()));
        List<Transition> ts = engine.decide(snap(0.9, s), cfg);
        assertEquals(1, ts.size());
        assertEquals(AlgorithmState.RECOVERING, ts.get(0).to());
    }

    @Test
    void dead_stays_before_cooldown() {
        var s = new AlgoSample("RS256", AlgorithmState.DEAD, 100.0, 0.5, msToNanos(cfg.getRecoverCooldownMs() - 1));
        assertTrue(engine.decide(snap(0.9, s), cfg).isEmpty());
    }

    @Test
    void recovering_to_active_on_recovered_metrics() {
        var s = new AlgoSample("RS256", AlgorithmState.RECOVERING, 5.0, 0.0, 0);
        List<Transition> ts = engine.decide(snap(0.9, s), cfg);
        assertEquals(1, ts.size());
        assertEquals(AlgorithmState.ACTIVE, ts.get(0).to());
    }

    @Test
    void recovering_stays_while_metrics_still_bad() {
        var s = new AlgoSample("RS256", AlgorithmState.RECOVERING, 100.0, 0.5, 0);
        assertTrue(engine.decide(snap(0.9, s), cfg).isEmpty());
    }

    @Test
    void score_formula_and_dead_zero() {
        // healthFactor = 1 - 50/100 = 0.5 ; successRate 1.0 -> 50
        assertEquals(50, PolicyEngine.score(AlgorithmState.ACTIVE, 50.0, 1.0, 100.0));
        assertEquals(0, PolicyEngine.score(AlgorithmState.DEAD, 1.0, 1.0, 100.0));
        // clamps negatives to 0
        assertEquals(0, PolicyEngine.score(AlgorithmState.ACTIVE, 200.0, 1.0, 100.0));
    }
}
