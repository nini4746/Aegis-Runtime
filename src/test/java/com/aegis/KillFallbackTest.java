package com.aegis;

import com.aegis.jws.TokenVerificationCache;
import com.aegis.jws.WorkerRegistry;
import com.aegis.lifecycle.AlgorithmState;
import com.aegis.lifecycle.KillReason;
import com.aegis.lifecycle.LifecycleActuator;
import com.aegis.lifecycle.LifecycleRegistry;
import com.aegis.lifecycle.Transition;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * D3/R4/R5 kill + fallback: killing RS256 invalidates only its cache entries, preserves key
 * material, still verifies existing tokens via the fallback path, and grants no new admission.
 * Context is dirtied afterward so the DEAD state never leaks into other @SpringBootTest classes.
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestPropertySource(properties = {
        "aegis.hs256.secret=test-secret-test-secret-test-secret-1234567890"
})
class KillFallbackTest {

    @Autowired private MockMvc mvc;
    @Autowired private WorkerRegistry workers;
    @Autowired private LifecycleRegistry lifecycles;
    @Autowired private LifecycleActuator actuator;
    @Autowired private TokenVerificationCache cache;

    private String issueRs256(String sub) {
        return Jwts.builder().subject(sub)
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(workers.rsaPrivate(), Jwts.SIG.RS256)
                .compact();
    }

    @Test
    void deadAlgorithmInvalidatesCacheKeepsKeyAndServesExistingTokenViaFallback() throws Exception {
        String token = issueRs256("kill-user");

        // 1) prime the cache with a normal verified request
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        assertNotNull(cache.get(token), "token must be cached after first verify");

        // 2) kill RS256 (ACTIVE -> THROTTLED -> DEAD)
        assertTrue(actuator.apply(new Transition("RS256", AlgorithmState.ACTIVE, AlgorithmState.THROTTLED, null)));
        assertTrue(actuator.apply(new Transition("RS256", AlgorithmState.THROTTLED, AlgorithmState.DEAD, KillReason.MEMORY_PRESSURE)));
        assertEquals(AlgorithmState.DEAD, lifecycles.stateOf("RS256"));

        // cache for RS256 was invalidated ...
        assertNull(cache.get(token), "kill must invalidate the algorithm's cache entries");
        // ... but the signing/verify key material is preserved
        assertNotNull(workers.forAlgorithm("RS256"), "kill must NOT delete key material");

        // 3) existing token still verifies via the DEAD fallback path (new admission bypassed)
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Aegis-Admission", "dead-fallback"));

        // fallback does NOT re-admit into the cache -> no new admission granted
        assertNull(cache.get(token), "DEAD fallback must not re-cache (no new admission)");
    }
}
