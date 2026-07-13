package com.aegis.lifecycle;

import com.aegis.jws.AlgorithmWorker;
import com.aegis.jws.CostCalculator;
import com.aegis.jws.WorkerRegistry;
import org.springframework.stereotype.Component;

/**
 * Production metric source: AlgorithmWorker EWMA (cost signal), the event-driven
 * metrics collector (failure signal), and CostCalculator.currentMemoryPressure() (D6).
 */
@Component
public class LiveMetricSource implements AlgorithmMetricSource {

    private final WorkerRegistry workers;
    private final AlgorithmMetricsCollector collector;

    public LiveMetricSource(WorkerRegistry workers, AlgorithmMetricsCollector collector) {
        this.workers = workers;
        this.collector = collector;
    }

    @Override
    public double avgVerifyMs(String algorithm) {
        AlgorithmWorker w = workers.forAlgorithm(algorithm);
        return w == null ? 0.0 : w.avgVerifyTimeMs();
    }

    @Override
    public double failureRate(String algorithm) {
        return collector.failureRate(algorithm);
    }

    @Override
    public double memoryPressure() {
        return CostCalculator.currentMemoryPressure();
    }
}
