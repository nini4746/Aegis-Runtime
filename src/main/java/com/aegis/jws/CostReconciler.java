package com.aegis.jws;

import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/**
 * Records the divergence between predicted scheduling cost (used to admit/reject)
 * and the cost computed from the actual verify-time observed for the request.
 * High divergence signals that cost estimates are stale — useful for tuning
 * EWMA decay or for raising an alarm before the scheduler starts mis-admitting.
 */
@Component
public class CostReconciler {

    private final DistributionSummary errorAbs;
    private final DistributionSummary errorPct;

    public CostReconciler(MeterRegistry meters) {
        this.errorAbs = DistributionSummary.builder("aegis.cost.reconciliation_error_abs")
                .description("Absolute difference between predicted and actual cost")
                .register(meters);
        this.errorPct = DistributionSummary.builder("aegis.cost.reconciliation_error_pct")
                .description("Relative error (predicted - actual) / max(predicted, actual)")
                .register(meters);
    }

    public void record(double predictedCost, long actualVerifyNanos, int tokenSizeBytes, double memoryPressure) {
        double actualMs = actualVerifyNanos / 1_000_000.0;
        double actualCost = CostCalculator.compute(actualMs, tokenSizeBytes, memoryPressure);
        double abs = Math.abs(predictedCost - actualCost);
        errorAbs.record(abs);
        double denom = Math.max(predictedCost, actualCost);
        if (denom > 0) {
            errorPct.record(abs / denom);
        }
    }
}
