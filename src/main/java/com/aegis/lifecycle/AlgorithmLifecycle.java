package com.aegis.lifecycle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * Per-algorithm state holder (R1). Only legal edges are applied; illegal edges are
 * ignored + logged. A nanos supplier is injected (D5) so dwell/cooldown timing is
 * driven by a fake clock in tests - no real sleep.
 */
public class AlgorithmLifecycle {

    private static final Logger log = LoggerFactory.getLogger(AlgorithmLifecycle.class);

    private static final Map<AlgorithmState, Set<AlgorithmState>> LEGAL = Map.of(
            AlgorithmState.ACTIVE, EnumSet.of(AlgorithmState.THROTTLED),
            AlgorithmState.THROTTLED, EnumSet.of(AlgorithmState.ACTIVE, AlgorithmState.DEAD),
            AlgorithmState.DEAD, EnumSet.of(AlgorithmState.RECOVERING),
            AlgorithmState.RECOVERING, EnumSet.of(AlgorithmState.ACTIVE)
    );

    private final String algorithm;
    private final LongSupplier nanos;

    private volatile AlgorithmState state = AlgorithmState.ACTIVE;
    private volatile long stateEnteredNanos;
    private volatile KillReason lastKillReason;

    public AlgorithmLifecycle(String algorithm, LongSupplier nanos) {
        this.algorithm = algorithm;
        this.nanos = nanos;
        this.stateEnteredNanos = nanos.getAsLong();
    }

    public String algorithm() { return algorithm; }
    public AlgorithmState state() { return state; }
    public long stateEnteredNanos() { return stateEnteredNanos; }
    public KillReason lastKillReason() { return lastKillReason; }

    /** DEAD => new admission refused (D3/R4). */
    public boolean admissionRejected() { return state == AlgorithmState.DEAD; }

    /**
     * Apply a transition if it is a legal edge. Returns true when applied.
     * Same-state and illegal edges are no-ops (illegal is logged).
     */
    public synchronized boolean transitionTo(AlgorithmState to, KillReason reason) {
        if (to == state) return false;
        if (!LEGAL.getOrDefault(state, Set.of()).contains(to)) {
            log.warn("illegal lifecycle edge {} {}->{} ignored", algorithm, state, to);
            return false;
        }
        AlgorithmState from = state;
        this.state = to;
        this.stateEnteredNanos = nanos.getAsLong();
        if (to == AlgorithmState.DEAD) {
            this.lastKillReason = reason;
        }
        log.info("lifecycle {} {}->{}{}", algorithm, from, to, reason == null ? "" : " (" + reason + ")");
        return true;
    }
}
