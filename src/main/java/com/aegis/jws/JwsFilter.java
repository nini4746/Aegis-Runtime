package com.aegis.jws;

import com.aegis.events.JwsRejectedEvent;
import com.aegis.events.JwsVerifiedEvent;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

@Component
public class JwsFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwsFilter.class);

    private final WorkerRegistry workers;
    private final CostAwareScheduler scheduler;
    private final ApplicationEventPublisher events;
    private final Counter okCounter;
    private final Counter failCounter;
    private final Timer verifyTimer;

    public JwsFilter(WorkerRegistry workers, CostAwareScheduler scheduler,
                     ApplicationEventPublisher events, MeterRegistry meters) {
        this.workers = workers;
        this.scheduler = scheduler;
        this.events = events;
        this.okCounter = Counter.builder("aegis.verify.success").register(meters);
        this.failCounter = Counter.builder("aegis.verify.failure").register(meters);
        this.verifyTimer = Timer.builder("aegis.verify.latency").register(meters);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String header = req.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "missing bearer token");
            return;
        }
        String token = header.substring(7);
        String alg = JwsHeaderInspector.algorithm(token);
        if (alg == null) {
            failCounter.increment();
            events.publishEvent(new JwsRejectedEvent("malformed-header", "unknown", 0.0));
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "malformed token");
            return;
        }
        AlgorithmWorker worker = workers.forAlgorithm(alg);
        if (worker == null) {
            failCounter.increment();
            events.publishEvent(new JwsRejectedEvent("unsupported-algorithm", alg, 0.0));
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unsupported algorithm: " + alg);
            return;
        }
        int tokenSize = token.getBytes(StandardCharsets.UTF_8).length;
        double cost = CostCalculator.compute(worker.avgVerifyTimeMs(), tokenSize, CostCalculator.currentMemoryPressure());
        if (!scheduler.tryAdmit(cost)) {
            events.publishEvent(new JwsRejectedEvent("scheduler-busy", alg, cost));
            res.setHeader("X-Aegis-Cost", String.valueOf(cost));
            res.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "verifier overloaded");
            return;
        }
        long start = System.nanoTime();
        try {
            Jws<Claims> jws = worker.verify(token);
            long delta = System.nanoTime() - start;
            verifyTimer.record(delta, TimeUnit.NANOSECONDS);
            okCounter.increment();
            events.publishEvent(new JwsVerifiedEvent(alg, jws.getPayload().getSubject(), cost, delta));
            req.setAttribute("aegis.subject", jws.getPayload().getSubject());
            req.setAttribute("aegis.algorithm", alg);
            chain.doFilter(req, res);
        } catch (Exception e) {
            failCounter.increment();
            events.publishEvent(new JwsRejectedEvent("verify-failed:" + e.getClass().getSimpleName(), alg, cost));
            log.debug("verify failed: {}", e.getMessage());
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "invalid token");
        } finally {
            scheduler.release();
        }
    }
}
