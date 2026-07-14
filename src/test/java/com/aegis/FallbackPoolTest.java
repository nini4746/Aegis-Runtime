package com.aegis;

import com.aegis.jws.AdmissionGate;
import com.aegis.jws.WorkerRegistry;
import com.aegis.lifecycle.AlgorithmState;
import com.aegis.lifecycle.KillReason;
import com.aegis.lifecycle.LifecycleActuator;
import com.aegis.lifecycle.LifecycleRegistry;
import com.aegis.lifecycle.Transition;
import com.aegis.support.LatchEndpoint;
import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * R10/D8 DEAD-fallback isolation pool. A DEAD algorithm verifies still-valid tokens only inside a
 * dedicated Semaphore of size {@code policy.fallback.max-concurrent} (2). Saturating the pool
 * rejects the next request with 503 + {@code X-Aegis-Admission: fallback-saturated} and never
 * touches the global scheduler. Once a slot frees, normal fallback (200 + dead-fallback) resumes.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestPropertySource(properties = {
        "aegis.hs256.secret=test-secret-test-secret-test-secret-1234567890"
})
class FallbackPoolTest {

    @Autowired private MockMvc mvc;
    @Autowired private WorkerRegistry workers;
    @Autowired private LifecycleRegistry lifecycles;
    @Autowired private LifecycleActuator actuator;
    @Autowired private AdmissionGate gate;
    @Autowired private MeterRegistry meters;

    @AfterEach
    void tearDown() {
        LatchEndpoint.reset();
    }

    private String issueRs256(String sub) {
        return Jwts.builder().subject(sub)
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(workers.rsaPrivate(), Jwts.SIG.RS256).compact();
    }

    private double counter(String name) {
        Counter c = meters.find(name).counter();
        return c == null ? 0.0 : c.count();
    }

    private void forceDead(String alg) {
        assertTrue(actuator.apply(new Transition(alg, AlgorithmState.ACTIVE, AlgorithmState.THROTTLED, null)));
        assertTrue(actuator.apply(new Transition(alg, AlgorithmState.THROTTLED, AlgorithmState.DEAD, KillReason.MEMORY_PRESSURE)));
        assertEquals(AlgorithmState.DEAD, lifecycles.stateOf(alg));
    }

    @Test
    void saturatedFallbackPoolRejectsThenRecovers() throws Exception {
        int pool = gate.fallbackMaxConcurrent();
        forceDead("RS256");

        CountDownLatch arrived = new CountDownLatch(pool);
        CountDownLatch open = new CountDownLatch(1);
        LatchEndpoint.arrived = arrived;
        LatchEndpoint.gate = open;

        ExecutorService exec = Executors.newFixedThreadPool(pool);
        for (int i = 0; i < pool; i++) {
            String token = issueRs256("fallback-hold-" + i);
            exec.submit(() -> mvc.perform(get("/api/latched").header("Authorization", "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(header().string("X-Aegis-Admission", "dead-fallback")));
        }
        // both fallback slots are now occupied by parked requests
        assertTrue(arrived.await(5, TimeUnit.SECONDS), "fallback requests must reach controller");
        assertEquals(0, gate.fallbackAvailable(), "fallback pool fully occupied");

        double admittedBefore = counter("aegis.scheduler.admitted");
        double rejectedBefore = counter("aegis.scheduler.rejected");

        // the extra DEAD request finds the pool saturated -> 503 fallback-saturated
        mvc.perform(get("/api/latched").header("Authorization", "Bearer " + issueRs256("fallback-extra")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string("X-Aegis-Admission", "fallback-saturated"));

        assertEquals(admittedBefore, counter("aegis.scheduler.admitted"), "saturated fallback must not touch global scheduler");
        assertEquals(rejectedBefore, counter("aegis.scheduler.rejected"), "saturated fallback must not touch global scheduler");

        // release the parked requests and let the pool drain
        open.countDown();
        exec.shutdown();
        assertTrue(exec.awaitTermination(5, TimeUnit.SECONDS));
        assertEquals(pool, gate.fallbackAvailable(), "pool fully released (no leak)");

        // pool has room again -> normal fallback semantics resume
        LatchEndpoint.reset();
        mvc.perform(get("/api/latched").header("Authorization", "Bearer " + issueRs256("fallback-after")))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Aegis-Admission", "dead-fallback"));
        assertEquals(pool, gate.fallbackAvailable(), "pool released after recovery request too");
    }
}
