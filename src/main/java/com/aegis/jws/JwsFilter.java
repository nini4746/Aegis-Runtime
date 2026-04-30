package com.aegis.jws;

import com.aegis.events.JwsRejectedEvent;
import com.aegis.events.JwsVerifiedEvent;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
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
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Component
public class JwsFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwsFilter.class);
    // explicit allowlist: even if WorkerRegistry contains a key, only these JWS algorithms
    // are accepted from the wire. This blocks "alg":"none" / unsigned JWTs and any algorithm
    // confusion attacks at the filter boundary, before any worker lookup.
    private static final Set<String> ALLOWED_ALGORITHMS = Set.of("HS256", "RS256", "ES256");

    private final WorkerRegistry workers;
    private final CostAwareScheduler scheduler;
    private final TokenVerificationCache cache;
    private final SubjectRateLimiter rateLimiter;
    private final CostReconciler reconciler;
    private final ApplicationEventPublisher events;
    private final MeterRegistry meters;
    private final Counter okCounter;
    private final Counter failCounter;
    private final Timer verifyTimer;

    public JwsFilter(WorkerRegistry workers, CostAwareScheduler scheduler,
                     TokenVerificationCache cache,
                     SubjectRateLimiter rateLimiter,
                     CostReconciler reconciler,
                     ApplicationEventPublisher events, MeterRegistry meters) {
        this.workers = workers;
        this.scheduler = scheduler;
        this.cache = cache;
        this.rateLimiter = rateLimiter;
        this.reconciler = reconciler;
        this.events = events;
        this.meters = meters;
        this.okCounter = Counter.builder("aegis.verify.success").register(meters);
        this.failCounter = Counter.builder("aegis.verify.failure").register(meters);
        this.verifyTimer = Timer.builder("aegis.verify.latency").register(meters);
    }

    private void recordReason(String reason, String alg) {
        Counter.builder("aegis.verify.rejected_reason")
                .tags(Tags.of("reason", reason, "algorithm", alg))
                .register(meters)
                .increment();
    }

    private void recordPerAlgo(String result, String alg) {
        Counter.builder("aegis.verify.by_algorithm")
                .tags(Tags.of("result", result, "algorithm", alg))
                .register(meters)
                .increment();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path.startsWith("/.well-known/")) return true;
        if (path.startsWith("/actuator/")) return true;
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

        Jws<Claims> cached = cache.get(token);
        if (cached != null) {
            String alg = cached.getHeader().getAlgorithm();
            String subject = cached.getPayload().getSubject();
            if (!rateLimiter.tryAcquire(subject)) {
                failCounter.increment();
                recordReason("rate-limit", alg);
                events.publishEvent(new JwsRejectedEvent("rate-limit", alg, 0.0));
                res.setHeader("X-Aegis-Subject", subject == null ? "" : subject);
                res.sendError(429, "rate limit exceeded");
                return;
            }
            okCounter.increment();
            recordPerAlgo("success", alg);
            events.publishEvent(new JwsVerifiedEvent(alg, subject, 0.0, 0L));
            req.setAttribute("aegis.subject", subject);
            req.setAttribute("aegis.algorithm", alg);
            req.setAttribute("aegis.cache", "hit");
            chain.doFilter(req, res);
            return;
        }

        String alg = JwsHeaderInspector.algorithm(token);
        if (alg == null) {
            failCounter.increment();
            recordReason("malformed-header", "unknown");
            events.publishEvent(new JwsRejectedEvent("malformed-header", "unknown", 0.0));
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "malformed token");
            return;
        }
        if (!ALLOWED_ALGORITHMS.contains(alg)) {
            failCounter.increment();
            recordReason("disallowed-algorithm", alg);
            events.publishEvent(new JwsRejectedEvent("disallowed-algorithm", alg, 0.0));
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "disallowed algorithm: " + alg);
            return;
        }
        AlgorithmWorker worker = workers.forAlgorithm(alg);
        if (worker == null) {
            failCounter.increment();
            recordReason("unsupported-algorithm", alg);
            events.publishEvent(new JwsRejectedEvent("unsupported-algorithm", alg, 0.0));
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unsupported algorithm: " + alg);
            return;
        }
        int tokenSize = token.getBytes(StandardCharsets.UTF_8).length;
        double memPressure = CostCalculator.currentMemoryPressure();
        double cost = CostCalculator.compute(worker.avgVerifyTimeMs(), tokenSize, memPressure);
        // tryAdmit only acquires a permit when it returns true; on false no permit is held,
        // so release() must be paired ONLY with the true branch via the finally below.
        if (!scheduler.tryAdmit(cost)) {
            recordReason("scheduler-busy", alg);
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
            String subject = jws.getPayload().getSubject();
            // rate-limit AFTER signature verification so the cost of verifying spam tokens
            // still counts against the misbehaving subject's bucket.
            if (!rateLimiter.tryAcquire(subject)) {
                failCounter.increment();
                recordReason("rate-limit", alg);
                events.publishEvent(new JwsRejectedEvent("rate-limit", alg, cost));
                res.setHeader("X-Aegis-Subject", subject == null ? "" : subject);
                res.sendError(429, "rate limit exceeded");
                return;
            }
            reconciler.record(cost, delta, tokenSize, memPressure);
            okCounter.increment();
            recordPerAlgo("success", alg);
            cache.put(token, jws);
            events.publishEvent(new JwsVerifiedEvent(alg, subject, cost, delta));
            req.setAttribute("aegis.subject", subject);
            req.setAttribute("aegis.algorithm", alg);
            req.setAttribute("aegis.cache", "miss");
            chain.doFilter(req, res);
        } catch (Exception e) {
            failCounter.increment();
            recordReason("verify-failed", alg);
            recordPerAlgo("failure", alg);
            events.publishEvent(new JwsRejectedEvent("verify-failed:" + e.getClass().getSimpleName(), alg, cost));
            log.debug("verify failed: {}", e.getMessage());
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "invalid token");
        } finally {
            scheduler.release();
        }
    }
}
