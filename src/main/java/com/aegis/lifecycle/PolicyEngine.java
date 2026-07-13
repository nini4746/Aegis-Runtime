package com.aegis.lifecycle;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * PURE decision function (R2): no clock, no I/O, no state. Given a snapshot and config
 * it returns the transitions to apply. Deterministic, unit-testable without Spring.
 *
 * D1 rules:
 *  - ACTIVE -> THROTTLED : avgVerifyMs > throttleLatencyMs OR failureRate > throttleFailureRate
 *  - THROTTLED -> ACTIVE : metrics back below both thresholds (de-throttle; lets min-share heal)
 *  - THROTTLED -> DEAD   : dwell >= deadDwellMs AND memoryPressure > killMemoryPressure,
 *                          algorithm not min-share protected. Among simultaneous candidates,
 *                          kill-order decides priority and AT MOST ONE is killed per tick.
 *  - DEAD -> RECOVERING  : dwell >= recoverCooldownMs
 *  - RECOVERING -> ACTIVE: metrics below both thresholds on a sample
 */
@Component
public class PolicyEngine {

    public List<Transition> decide(PolicySnapshot snap, PolicyProperties cfg) {
        List<Transition> out = new ArrayList<>();
        List<AlgoSample> deadCandidates = new ArrayList<>();

        for (AlgoSample s : snap.samples().values()) {
            switch (s.state()) {
                case ACTIVE -> {
                    if (s.avgVerifyMs() > cfg.getThrottleLatencyMs()
                            || s.failureRate() > cfg.getThrottleFailureRate()) {
                        out.add(new Transition(s.algorithm(), AlgorithmState.ACTIVE, AlgorithmState.THROTTLED, null));
                    }
                }
                case THROTTLED -> {
                    boolean healthy = s.avgVerifyMs() < cfg.getThrottleLatencyMs()
                            && s.failureRate() < cfg.getThrottleFailureRate();
                    if (healthy) {
                        out.add(new Transition(s.algorithm(), AlgorithmState.THROTTLED, AlgorithmState.ACTIVE, null));
                    } else if (!cfg.getMinShare().containsKey(s.algorithm())
                            && s.nanosInState() >= cfg.getDeadDwellMs() * 1_000_000L
                            && snap.memoryPressure() > cfg.getKillMemoryPressure()) {
                        deadCandidates.add(s);
                    }
                }
                case DEAD -> {
                    if (s.nanosInState() >= cfg.getRecoverCooldownMs() * 1_000_000L) {
                        out.add(new Transition(s.algorithm(), AlgorithmState.DEAD, AlgorithmState.RECOVERING, null));
                    }
                }
                case RECOVERING -> {
                    if (s.avgVerifyMs() < cfg.getThrottleLatencyMs()
                            && s.failureRate() < cfg.getThrottleFailureRate()) {
                        out.add(new Transition(s.algorithm(), AlgorithmState.RECOVERING, AlgorithmState.ACTIVE, null));
                    }
                }
            }
        }

        if (!deadCandidates.isEmpty()) {
            List<String> order = cfg.getKillOrder();
            deadCandidates.sort(Comparator.comparingInt(s -> {
                int i = order.indexOf(s.algorithm());
                return i < 0 ? Integer.MAX_VALUE : i;
            }));
            AlgoSample victim = deadCandidates.get(0);
            out.add(new Transition(victim.algorithm(), AlgorithmState.THROTTLED, AlgorithmState.DEAD,
                    KillReason.MEMORY_PRESSURE));
        }
        return out;
    }

    /**
     * D2 leaderboard score. Deterministic. DEAD scores 0.
     * healthFactor = clamp(1 - avgVerifyMs/ceiling, 0, 1); score = round(100 * healthFactor * successRate).
     */
    public static int score(AlgorithmState state, double avgVerifyMs, double successRate, double ceilingMs) {
        if (state == AlgorithmState.DEAD) return 0;
        double ceiling = ceilingMs <= 0 ? 1.0 : ceilingMs;
        double healthFactor = Math.max(0.0, Math.min(1.0, 1.0 - avgVerifyMs / ceiling));
        double sr = Math.max(0.0, Math.min(1.0, successRate));
        return (int) Math.round(100.0 * healthFactor * sr);
    }
}
