package com.aegis.lifecycle;

/**
 * Per-algorithm input to the PolicyEngine. nanosInState is supplied by the caller
 * (now - stateEnteredNanos) so the engine stays pure - no clock, no I/O.
 */
public record AlgoSample(String algorithm,
                         AlgorithmState state,
                         double avgVerifyMs,
                         double failureRate,
                         long nanosInState) {}
