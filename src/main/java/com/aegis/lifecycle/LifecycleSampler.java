package com.aegis.lifecycle;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * Periodic sampler (R3): builds a PolicySnapshot from the metric source + lifecycle
 * clocks, asks the pure PolicyEngine for transitions, and applies them via the actuator.
 *
 * The @Scheduled method just delegates to {@link #tick()}, which is public and takes no
 * hidden dependency on real time - tests call tick() directly with a fake clock and a
 * fake metric source for deterministic dwell/cooldown assertions (no real sleep).
 */
@Component
public class LifecycleSampler {

    private final LifecycleRegistry registry;
    private final AlgorithmMetricSource metrics;
    private final PolicyEngine engine;
    private final PolicyProperties config;
    private final LifecycleActuator actuator;
    private final LongSupplier nanos;

    public LifecycleSampler(LifecycleRegistry registry,
                            AlgorithmMetricSource metrics,
                            PolicyEngine engine,
                            PolicyProperties config,
                            LifecycleActuator actuator,
                            LongSupplier nanos) {
        this.registry = registry;
        this.metrics = metrics;
        this.engine = engine;
        this.config = config;
        this.actuator = actuator;
        this.nanos = nanos;
    }

    @Scheduled(fixedDelayString = "${policy.sample-interval-ms:60000}")
    public void scheduledTick() {
        tick();
    }

    /** Directly callable for deterministic tests. Returns the transitions applied. */
    public List<Transition> tick() {
        long now = nanos.getAsLong();
        double memoryPressure = metrics.memoryPressure();
        Map<String, AlgoSample> samples = new LinkedHashMap<>();
        for (String alg : registry.algorithms()) {
            AlgorithmLifecycle lc = registry.lifecycle(alg);
            long nanosInState = now - lc.stateEnteredNanos();
            samples.put(alg, new AlgoSample(alg, lc.state(),
                    metrics.avgVerifyMs(alg), metrics.failureRate(alg), nanosInState));
        }
        List<Transition> transitions = engine.decide(new PolicySnapshot(samples, memoryPressure), config);
        for (Transition t : transitions) {
            actuator.apply(t);
        }
        return transitions;
    }
}
