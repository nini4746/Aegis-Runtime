package com.aegis.lifecycle;

import com.aegis.events.JwsRejectedEvent;
import com.aegis.events.JwsVerifiedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;

/**
 * Aggregates the per-algorithm verify signal by subscribing to JwsVerifiedEvent /
 * JwsRejectedEvent.
 *
 * Why events rather than reading the Micrometer `aegis.verify.by_algorithm` counter back:
 *  - the events carry `algorithm` on every path and fire once per outcome, so we control
 *    the aggregation semantics instead of diffing a monotonic cumulative counter;
 *  - only genuine verification failures (reason "verify-failed*") count against an
 *    algorithm's health - rate-limit / scheduler-busy rejections are not the algo's fault,
 *    matching exactly what the by_algorithm counter records;
 *  - trivially testable: feed events or bypass entirely via a fake metric source.
 * Counts are cumulative; failureRate/successRate are ratios over all observations.
 */
@Component
public class AlgorithmMetricsCollector {

    private final Map<String, LongAdder> successes = new ConcurrentHashMap<>();
    private final Map<String, LongAdder> failures = new ConcurrentHashMap<>();

    @EventListener
    public void onVerified(JwsVerifiedEvent e) {
        successes.computeIfAbsent(e.algorithm(), k -> new LongAdder()).increment();
    }

    @EventListener
    public void onRejected(JwsRejectedEvent e) {
        if (e.reason() != null && e.reason().startsWith("verify-failed")) {
            failures.computeIfAbsent(e.algorithm(), k -> new LongAdder()).increment();
        }
    }

    public long success(String alg) {
        LongAdder a = successes.get(alg);
        return a == null ? 0 : a.sum();
    }

    public long failure(String alg) {
        LongAdder a = failures.get(alg);
        return a == null ? 0 : a.sum();
    }

    public double failureRate(String alg) {
        long ok = success(alg);
        long bad = failure(alg);
        long total = ok + bad;
        return total == 0 ? 0.0 : bad / (double) total;
    }

    public double successRate(String alg) {
        long ok = success(alg);
        long bad = failure(alg);
        long total = ok + bad;
        return total == 0 ? 1.0 : ok / (double) total;
    }
}
