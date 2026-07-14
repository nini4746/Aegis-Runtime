package com.aegis.lifecycle;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * D1/D2 thresholds, kill-order and min-share, bound from the `policy` block (R7).
 * Also consumed directly by the pure PolicyEngine (plain data, no Spring coupling),
 * so unit tests can construct it with `new` + setters.
 */
@ConfigurationProperties("policy")
public class PolicyProperties {

    /** ACTIVE -> THROTTLED when avgVerifyMs exceeds this. */
    private long throttleLatencyMs = 50;
    /** ACTIVE -> THROTTLED when failureRate exceeds this. */
    private double throttleFailureRate = 0.25;
    /** THROTTLED dwell before a kill is eligible. */
    private long deadDwellMs = 5000;
    /** THROTTLED -> DEAD only when memoryPressure exceeds this (D6 trigger). */
    private double killMemoryPressure = 0.85;
    /** DEAD -> RECOVERING after this cooldown. */
    private long recoverCooldownMs = 10000;
    /** D2 score: healthFactor = clamp(1 - avgVerifyMs/ceiling, 0, 1). */
    private long scoreLatencyCeilingMs = 100;
    /** @Scheduled sampler period. Large by default so short test suites never race a transition. */
    private long sampleIntervalMs = 60000;
    /** Priority for THROTTLED->DEAD when multiple candidates qualify in one tick (earlier = killed first). */
    private List<String> killOrder = new ArrayList<>(List.of("ES256", "RS256"));
    /** Algorithms protected from kill (THROTTLE only). Value = reserved share (informational). */
    private Map<String, Integer> minShare = new HashMap<>(Map.of("HS256", 30));
    /** R9/D7: per-algo THROTTLE in-flight cap, enforced outside the global scheduler. */
    private Throttle throttle = new Throttle();
    /** R10/D8: isolated DEAD-fallback direct-verification pool. */
    private Fallback fallback = new Fallback();

    public long getThrottleLatencyMs() { return throttleLatencyMs; }
    public void setThrottleLatencyMs(long v) { this.throttleLatencyMs = v; }

    public double getThrottleFailureRate() { return throttleFailureRate; }
    public void setThrottleFailureRate(double v) { this.throttleFailureRate = v; }

    public long getDeadDwellMs() { return deadDwellMs; }
    public void setDeadDwellMs(long v) { this.deadDwellMs = v; }

    public double getKillMemoryPressure() { return killMemoryPressure; }
    public void setKillMemoryPressure(double v) { this.killMemoryPressure = v; }

    public long getRecoverCooldownMs() { return recoverCooldownMs; }
    public void setRecoverCooldownMs(long v) { this.recoverCooldownMs = v; }

    public long getScoreLatencyCeilingMs() { return scoreLatencyCeilingMs; }
    public void setScoreLatencyCeilingMs(long v) { this.scoreLatencyCeilingMs = v; }

    public long getSampleIntervalMs() { return sampleIntervalMs; }
    public void setSampleIntervalMs(long v) { this.sampleIntervalMs = v; }

    public List<String> getKillOrder() { return killOrder; }
    public void setKillOrder(List<String> v) { this.killOrder = v; }

    public Map<String, Integer> getMinShare() { return minShare; }
    public void setMinShare(Map<String, Integer> v) { this.minShare = v; }

    public Throttle getThrottle() { return throttle; }
    public void setThrottle(Throttle v) { this.throttle = v; }

    public Fallback getFallback() { return fallback; }
    public void setFallback(Fallback v) { this.fallback = v; }

    /** Bound from `policy.throttle.max-concurrent` (D7, default 2). */
    public static class Throttle {
        private int maxConcurrent = 2;
        public int getMaxConcurrent() { return maxConcurrent; }
        public void setMaxConcurrent(int v) { this.maxConcurrent = v; }
    }

    /** Bound from `policy.fallback.max-concurrent` (D8, default 2). */
    public static class Fallback {
        private int maxConcurrent = 2;
        public int getMaxConcurrent() { return maxConcurrent; }
        public void setMaxConcurrent(int v) { this.maxConcurrent = v; }
    }
}
