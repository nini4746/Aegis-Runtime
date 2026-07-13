package com.aegis.lifecycle;

/**
 * Lifecycle state of a signature algorithm, modelled like an OS process.
 *  ACTIVE     - healthy, admits new work normally.
 *  THROTTLED  - degraded (latency/failure); prefer-reject under memory pressure.
 *  DEAD       - killed: new admission refused, verification cache invalidated,
 *               key material preserved (existing tokens served via fallback).
 *  RECOVERING - cooling down after a kill; promoted to ACTIVE once metrics recover.
 */
public enum AlgorithmState {
    ACTIVE,
    THROTTLED,
    DEAD,
    RECOVERING
}
