package com.aegis;

import com.aegis.jws.CostReconciler;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CostReconcilerTest {

    @Test
    void recordsErrorMetrics() {
        MeterRegistry meters = new SimpleMeterRegistry();
        CostReconciler r = new CostReconciler(meters);
        r.record(50.0, 1_000_000L, 2048, 0.1); // actual ~3 + 2 + 20 = 25 -> error 25
        var abs = meters.find("aegis.cost.reconciliation_error_abs").summary();
        assertNotNull(abs);
        assertEquals(1, abs.count());
        assertTrue(abs.totalAmount() > 0);
        var pct = meters.find("aegis.cost.reconciliation_error_pct").summary();
        assertNotNull(pct);
        assertEquals(1, pct.count());
    }

    @Test
    void zeroPredictedAndActualSkipsPctSummary() {
        MeterRegistry meters = new SimpleMeterRegistry();
        CostReconciler r = new CostReconciler(meters);
        r.record(0.0, 0L, 0, 0.0);
        var abs = meters.find("aegis.cost.reconciliation_error_abs").summary();
        var pct = meters.find("aegis.cost.reconciliation_error_pct").summary();
        assertNotNull(abs);
        assertEquals(1, abs.count());
        assertEquals(0, pct.count());
    }
}
