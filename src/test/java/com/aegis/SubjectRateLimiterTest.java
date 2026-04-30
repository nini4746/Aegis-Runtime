package com.aegis;

import com.aegis.jws.SubjectRateLimiter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SubjectRateLimiterTest {

    private SubjectRateLimiter newLimiter(int cap, double refill) {
        return new SubjectRateLimiter(new SimpleMeterRegistry(), true, cap, refill, 1024);
    }

    @Test
    void disabledLimiterAlwaysAllows() {
        SubjectRateLimiter rl = new SubjectRateLimiter(new SimpleMeterRegistry(), false, 1, 1.0, 1024);
        for (int i = 0; i < 100; i++) {
            assertTrue(rl.tryAcquire("u"));
        }
    }

    @Test
    void capacityIsEnforced() {
        SubjectRateLimiter rl = newLimiter(5, 0.0001);
        for (int i = 0; i < 5; i++) assertTrue(rl.tryAcquire("alice"), "consume " + i);
        assertFalse(rl.tryAcquire("alice"), "6th call must be rejected");
    }

    @Test
    void subjectsAreIndependent() {
        SubjectRateLimiter rl = newLimiter(2, 0.0001);
        assertTrue(rl.tryAcquire("alice"));
        assertTrue(rl.tryAcquire("alice"));
        assertFalse(rl.tryAcquire("alice"));
        assertTrue(rl.tryAcquire("bob"));
        assertTrue(rl.tryAcquire("bob"));
        assertFalse(rl.tryAcquire("bob"));
    }

    @Test
    void refillRestoresTokensOverTime() throws InterruptedException {
        SubjectRateLimiter rl = newLimiter(2, 100.0); // 100 tokens/sec
        assertTrue(rl.tryAcquire("u"));
        assertTrue(rl.tryAcquire("u"));
        assertFalse(rl.tryAcquire("u"));
        Thread.sleep(50); // 50ms -> ~5 tokens, capped at 2
        assertTrue(rl.tryAcquire("u"));
    }

    @Test
    void blankOrNullSubjectAlwaysAllowed() {
        SubjectRateLimiter rl = newLimiter(1, 0.0001);
        assertTrue(rl.tryAcquire(null));
        assertTrue(rl.tryAcquire(""));
        assertTrue(rl.tryAcquire("   "));
    }

    @Test
    void resetClearsState() {
        SubjectRateLimiter rl = newLimiter(1, 0.0001);
        assertTrue(rl.tryAcquire("u"));
        assertFalse(rl.tryAcquire("u"));
        rl.reset();
        assertTrue(rl.tryAcquire("u"));
    }
}
