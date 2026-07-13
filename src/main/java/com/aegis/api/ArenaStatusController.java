package com.aegis.api;

import com.aegis.lifecycle.AlgorithmLifecycle;
import com.aegis.lifecycle.AlgorithmMetricSource;
import com.aegis.lifecycle.AlgorithmMetricsCollector;
import com.aegis.lifecycle.AlgorithmState;
import com.aegis.lifecycle.KillReason;
import com.aegis.lifecycle.LifecycleRegistry;
import com.aegis.lifecycle.PolicyEngine;
import com.aegis.lifecycle.PolicyProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Leaderboard endpoint (R6): GET /admin/arena returns per-algorithm lifecycle status
 * with the D2 score. Not under /api/ so it is not gated by JwsFilter.
 */
@RestController
public class ArenaStatusController {

    private final LifecycleRegistry registry;
    private final AlgorithmMetricSource metrics;
    private final AlgorithmMetricsCollector collector;
    private final PolicyProperties config;

    public ArenaStatusController(LifecycleRegistry registry,
                                 AlgorithmMetricSource metrics,
                                 AlgorithmMetricsCollector collector,
                                 PolicyProperties config) {
        this.registry = registry;
        this.metrics = metrics;
        this.collector = collector;
        this.config = config;
    }

    @GetMapping("/admin/arena")
    public Map<String, Object> arena() {
        List<Map<String, Object>> leaderboard = new ArrayList<>();
        for (String alg : registry.algorithms()) {
            AlgorithmLifecycle lc = registry.lifecycle(alg);
            AlgorithmState state = lc.state();
            double avgVerifyMs = metrics.avgVerifyMs(alg);
            double successRate = collector.successRate(alg);
            int score = PolicyEngine.score(state, avgVerifyMs, successRate, config.getScoreLatencyCeilingMs());
            KillReason reason = lc.lastKillReason();

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("algorithm", alg);
            row.put("state", state.name());
            row.put("avgVerifyMs", avgVerifyMs);
            row.put("memoryPressure", metrics.memoryPressure());
            row.put("successRate", successRate);
            row.put("score", score);
            row.put("lastKillReason", reason == null ? null : reason.name());
            leaderboard.add(row);
        }
        // highest score first
        leaderboard.sort((a, b) -> Integer.compare((int) b.get("score"), (int) a.get("score")));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("leaderboard", leaderboard);
        return body;
    }
}
