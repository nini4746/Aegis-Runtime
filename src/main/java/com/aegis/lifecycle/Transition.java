package com.aegis.lifecycle;

/** A decided state change produced by the pure PolicyEngine. reason is non-null only for kills. */
public record Transition(String algorithm, AlgorithmState from, AlgorithmState to, KillReason reason) {}
