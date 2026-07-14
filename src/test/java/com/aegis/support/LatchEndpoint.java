package com.aegis.support;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 * Test-only downstream endpoint at {@code /api/latched} (so it passes through JwsFilter). A request
 * that reaches the controller counts down {@link #arrived} and then blocks on {@link #gate} while it
 * is non-null. This pins the request IN-FLIGHT - i.e. still holding whatever admission slot the
 * filter took (the R9 throttle counter, or the R10 fallback permit) - so concurrency caps can be
 * exercised deterministically with latches instead of sleeps. Both fields default to null, so the
 * endpoint is inert for every other test.
 */
@RestController
public class LatchEndpoint {

    public static volatile CountDownLatch gate;
    public static volatile CountDownLatch arrived;

    public static void reset() {
        gate = null;
        arrived = null;
    }

    @GetMapping("/api/latched")
    public Map<String, Object> latched() {
        CountDownLatch a = arrived;
        if (a != null) a.countDown();
        CountDownLatch g = gate;
        if (g != null) {
            try {
                g.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        return Map.of("ok", true);
    }
}
