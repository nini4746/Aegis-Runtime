package com.aegis;

import com.aegis.jws.SubjectRateLimiter;
import com.aegis.jws.WorkerRegistry;
import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Date;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "aegis.hs256.secret=test-secret-test-secret-test-secret-1234567890",
        "aegis.ratelimit.capacity=3",
        "aegis.ratelimit.refill-per-sec=0.0001"
})
class RateLimitFilterTest {

    @Autowired private MockMvc mvc;
    @Autowired private WorkerRegistry workers;
    @Autowired private SubjectRateLimiter rateLimiter;
    @Autowired private MeterRegistry meters;

    @BeforeEach
    void resetLimiter() {
        rateLimiter.reset();
    }

    private String issue(String sub) {
        return Jwts.builder().subject(sub)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(workers.hs256Secret()).compact();
    }

    @Test
    void perSubjectLimitReturns429AfterExhaust() throws Exception {
        // capacity=3 -> 4th request must be 429
        for (int i = 0; i < 3; i++) {
            // each request uses a fresh token to avoid the verification cache short-circuit
            String token = issue("limited-" + i);
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + token))
                    .andExpect(status().isOk());
            // limit by single subject:
        }
        // now hammer one subject
        String t1 = issue("u-burst");
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + t1))
                .andExpect(status().isOk());
        String t2 = issue("u-burst");
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + t2))
                .andExpect(status().isOk());
        String t3 = issue("u-burst");
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + t3))
                .andExpect(status().isOk());
        String t4 = issue("u-burst");
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + t4))
                .andExpect(status().is(429));
        var rejected = meters.find("aegis.ratelimit.rejected").counter();
        assertNotNull(rejected);
        assertTrue(rejected.count() >= 1);
    }

    @Test
    void differentSubjectsHaveSeparateBuckets() throws Exception {
        for (int i = 0; i < 3; i++) {
            String t = issue("alice");
            mvc.perform(get("/api/ping").header("Authorization", "Bearer " + t))
                    .andExpect(status().isOk());
        }
        // alice's bucket is empty; bob still has full capacity
        String tBob = issue("bob");
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + tBob))
                .andExpect(status().isOk());
    }

    @Test
    void costReconciliationMetricsAreEmitted() throws Exception {
        String token = issue("recon-" + System.nanoTime());
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        var s = meters.find("aegis.cost.reconciliation_error_abs").summary();
        assertNotNull(s);
        assertTrue(s.count() >= 1);
    }

    @Test
    void perAlgorithmCounterEmitted() throws Exception {
        String token = issue("by-algo-" + System.nanoTime());
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        var c = meters.find("aegis.verify.by_algorithm").tag("algorithm", "HS256").tag("result", "success").counter();
        assertNotNull(c);
        assertTrue(c.count() >= 1);
    }
}
