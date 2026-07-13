package com.aegis.lifecycle;

import java.util.Map;

/** Complete deterministic input for one PolicyEngine.decide() call. */
public record PolicySnapshot(Map<String, AlgoSample> samples, double memoryPressure) {}
