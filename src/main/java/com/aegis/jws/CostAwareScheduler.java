package com.aegis.jws;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class CostAwareScheduler {

    private final Semaphore permits;
    private final double rejectThreshold;
    private final AtomicInteger queueDepth = new AtomicInteger();

    private final Counter admitted;
    private final Counter rejected;
    private final Timer waitTimer;

    public CostAwareScheduler(MeterRegistry meters,
                              @Value("${aegis.scheduler.permits:8}") int maxPermits,
                              @Value("${aegis.scheduler.reject-threshold:250.0}") double rejectThreshold) {
        this.permits = new Semaphore(maxPermits);
        this.rejectThreshold = rejectThreshold;
        this.admitted = Counter.builder("aegis.scheduler.admitted").register(meters);
        this.rejected = Counter.builder("aegis.scheduler.rejected").register(meters);
        this.waitTimer = Timer.builder("aegis.scheduler.wait").register(meters);
        meters.gauge("aegis.scheduler.queue_depth", queueDepth);
    }

    public boolean tryAdmit(double cost) {
        if (cost > rejectThreshold) {
            if (!permits.tryAcquire()) {
                rejected.increment();
                return false;
            }
            admitted.increment();
            return true;
        }
        long waitMs = waitMillisFor(cost);
        long start = System.nanoTime();
        queueDepth.incrementAndGet();
        try {
            boolean ok = permits.tryAcquire(waitMs, TimeUnit.MILLISECONDS);
            waitTimer.record(System.nanoTime() - start, TimeUnit.NANOSECONDS);
            if (ok) {
                admitted.increment();
                return true;
            }
            rejected.increment();
            return false;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            rejected.increment();
            return false;
        } finally {
            queueDepth.decrementAndGet();
        }
    }

    public void release() {
        permits.release();
    }

    private long waitMillisFor(double cost) {
        if (cost < 50) return 100;
        if (cost < 100) return 60;
        if (cost < 200) return 30;
        return 10;
    }

    int currentQueueDepth() { return queueDepth.get(); }
}
