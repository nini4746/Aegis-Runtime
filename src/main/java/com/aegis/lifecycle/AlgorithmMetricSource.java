package com.aegis.lifecycle;

/**
 * Seam the sampler reads cost/health signals through. The live implementation wires
 * the real AlgorithmWorker EWMA + metrics collector + memory pressure; tests supply a
 * fake so sampler ticks are fully deterministic (no real clock, no real metrics).
 */
public interface AlgorithmMetricSource {
    double avgVerifyMs(String algorithm);
    double failureRate(String algorithm);
    double memoryPressure();
}
