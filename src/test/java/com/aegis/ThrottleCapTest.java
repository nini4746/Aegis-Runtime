package com.aegis;

import com.aegis.jws.AdmissionGate;
import com.aegis.jws.WorkerRegistry;
import com.aegis.lifecycle.AlgorithmState;
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
 * R9/D7 per-algo THROTTLE cap. A THROTTLED algorithm admits at most
 * {@code policy.throttle.max-concurrent} (2) in-flight verifications; the extra gets a 503 with
 * {@code X-Aegis-Lifecycle: THROTTLED-cap} and does NOT consume a global scheduler permit. An
 * ACTIVE algorithm under the same load pays no cap. Context is dirtied so the forced THROTTLED
 * state never leaks into other @SpringBootTest classes.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestPropertySource(properties = {
        "aegis.hs256.secret=test-secret-test-secret-test-secret-1234567890"
})
class ThrottleCapTest {

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

    private String issueEs256(String sub) {
        return Jwts.builder().subject(sub)
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(workers.ecPrivate(), Jwts.SIG.ES256).compact();
    }

    private String issueHs256(String sub) {
        return Jwts.builder().subject(sub)
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(workers.hs256Secret()).compact();
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

    private void forceThrottled(String alg) {
        assertTrue(actuator.apply(new Transition(alg, AlgorithmState.ACTIVE, AlgorithmState.THROTTLED, null)));
        assertEquals(AlgorithmState.THROTTLED, lifecycles.stateOf(alg));
    }

    @Test
    void throttledAlgoCapsInFlightAndExtraGets503WithoutTouchingGlobalScheduler() throws Exception {
        int cap = gate.throttleMaxConcurrent();
        forceThrottled("ES256");

        CountDownLatch arrived = new CountDownLatch(cap);
        CountDownLatch open = new CountDownLatch(1);
        LatchEndpoint.arrived = arrived;
        LatchEndpoint.gate = open;

        ExecutorService pool = Executors.newFixedThreadPool(cap);
        for (int i = 0; i < cap; i++) {
            String token = issueEs256("cap-hold-" + i);
            pool.submit(() -> mvc.perform(get("/api/latched").header("Authorization", "Bearer " + token))
                    .andExpect(status().isOk()));
        }
        // all `cap` requests are now parked inside the controller, each still holding a throttle slot
        assertTrue(arrived.await(5, TimeUnit.SECONDS), "pinned requests must reach controller");
        assertEquals(cap, gate.inFlight("ES256"), "exactly cap in-flight");

        double admittedBefore = counter("aegis.scheduler.admitted");
        double rejectedBefore = counter("aegis.scheduler.rejected");

        // the extra request exceeds the cap -> 503 THROTTLED-cap, global scheduler untouched
        mvc.perform(get("/api/latched").header("Authorization", "Bearer " + issueEs256("cap-extra")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string("X-Aegis-Lifecycle", "THROTTLED-cap"));

        assertEquals(admittedBefore, counter("aegis.scheduler.admitted"), "cap reject must not admit a global permit");
        assertEquals(rejectedBefore, counter("aegis.scheduler.rejected"), "cap reject must not reach the global scheduler");

        open.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        assertEquals(0, gate.inFlight("ES256"), "counter back to 0 after release (no leak)");
    }

    @Test
    void activeAlgoUnderSameLoadPaysNoCap() throws Exception {
        int over = gate.throttleMaxConcurrent() + 1; // more than the throttle cap
        // RS256 stays ACTIVE (never throttled here) -> cap must not apply
        assertEquals(AlgorithmState.ACTIVE, lifecycles.stateOf("RS256"));

        CountDownLatch arrived = new CountDownLatch(over);
        CountDownLatch open = new CountDownLatch(1);
        LatchEndpoint.arrived = arrived;
        LatchEndpoint.gate = open;

        ExecutorService pool = Executors.newFixedThreadPool(over);
        for (int i = 0; i < over; i++) {
            String token = issueRs256("active-hold-" + i);
            pool.submit(() -> mvc.perform(get("/api/latched").header("Authorization", "Bearer " + token))
                    .andExpect(status().isOk()));
        }
        // all `over` requests pass through even though over > throttle cap: ACTIVE pays no cap
        assertTrue(arrived.await(5, TimeUnit.SECONDS), "all ACTIVE requests must pass (no cap)");
        assertEquals(0, gate.inFlight("RS256"), "ACTIVE algo never touches the throttle counter");

        open.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
    }

    @Test
    void throttleCounterReleasedOnVerifyException() throws Exception {
        // distinct algo (HS256) so this method never collides with the ES256/RS256 methods that
        // share the same @DirtiesContext(AFTER_CLASS) context.
        forceThrottled("HS256");
        String good = issueHs256("leak-user");
        String tampered = good.substring(0, good.length() - 4) + "xxxx";
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized());
        assertEquals(0, gate.inFlight("HS256"), "throttle counter released on the exception path");
    }
}
