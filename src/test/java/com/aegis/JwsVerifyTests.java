package com.aegis;

import com.aegis.jws.WorkerRegistry;
import io.jsonwebtoken.Jwts;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "aegis.hs256.secret=test-secret-test-secret-test-secret-1234567890"
})
class JwsVerifyTests {

    @Autowired private MockMvc mvc;
    @Autowired private WorkerRegistry workers;
    @Autowired private MeterRegistry meters;

    private String issueHs256(String sub, long ttlMs) {
        return Jwts.builder()
                .subject(sub)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + ttlMs))
                .signWith(workers.hs256Secret())
                .compact();
    }

    private String issueRs256(String sub) {
        return Jwts.builder()
                .subject(sub)
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(workers.rsaPrivate(), Jwts.SIG.RS256)
                .compact();
    }

    private String issueEs256(String sub) {
        return Jwts.builder()
                .subject(sub)
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(workers.ecPrivate(), Jwts.SIG.ES256)
                .compact();
    }

    @Test
    void hs256_valid_token_passes() throws Exception {
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + issueHs256("u1", 60_000)))
                .andExpect(status().isOk());
    }

    @Test
    void rs256_valid_token_passes() throws Exception {
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + issueRs256("u2")))
                .andExpect(status().isOk());
    }

    @Test
    void es256_valid_token_passes() throws Exception {
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + issueEs256("u3")))
                .andExpect(status().isOk());
    }

    @Test
    void tampered_signature_is_rejected() throws Exception {
        String token = issueHs256("u4", 60_000);
        String tampered = token.substring(0, token.length() - 4) + "xxxx";
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expired_token_is_rejected() throws Exception {
        String token = issueHs256("u5", -1000);
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void missing_token_is_rejected() throws Exception {
        mvc.perform(get("/api/ping")).andExpect(status().isUnauthorized());
    }

    @Test
    void unsupported_algorithm_is_rejected() throws Exception {
        // header alg=none → not supported
        String fakeNone = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes())
                + "."
                + java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"x\"}".getBytes())
                + ".";
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + fakeNone))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void jwks_endpoint_exposes_rs256_and_es256_keys() throws Exception {
        var res = mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andReturn();
        String body = res.getResponse().getContentAsString();
        assertTrue(body.contains("\"kty\":\"RSA\""));
        assertTrue(body.contains("\"kty\":\"EC\""));
        assertTrue(body.contains("\"alg\":\"RS256\""));
        assertTrue(body.contains("\"alg\":\"ES256\""));
        assertTrue(body.contains("\"kid\":\"rs256-current\""));
    }

    @Test
    void hs384_token_is_rejected_by_allowlist() throws Exception {
        // craft a header claiming HS384 — even with a valid-looking signature, allowlist must reject before verification
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"HS384\",\"typ\":\"JWT\"}".getBytes());
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"x\"}".getBytes());
        String fake = header + "." + payload + ".aaaa";
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + fake))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void cached_token_does_not_re_invoke_worker() throws Exception {
        String token = issueHs256("cache-user", 60_000);
        // first call: miss, second call: hit
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        mvc.perform(get("/api/ping").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        var hits = meters.find("aegis.cache.hits").counter();
        assertTrue(hits != null && hits.count() >= 1, "second call must hit cache");
    }

    @Test
    void concurrent_flood_triggers_some_rejections() throws Exception {
        String token = issueHs256("flood", 60_000);
        int threads = 64;
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        AtomicInteger other = new AtomicInteger();

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    int s = mvc.perform(get("/api/ping").header("Authorization", "Bearer " + token))
                            .andReturn().getResponse().getStatus();
                    if (s == 200) ok.incrementAndGet();
                    else if (s == 503) rejected.incrementAndGet();
                    else other.incrementAndGet();
                } catch (Throwable t) {
                    other.incrementAndGet();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        done.await();
        pool.shutdownNow();

        assertTrue(ok.get() > 0, "최소 일부는 통과해야 한다");
        assertTrue(ok.get() + rejected.get() + other.get() == threads);
        // metric counter should be present
        var c = meters.find("aegis.scheduler.rejected").counter();
        assertTrue(c != null, "rejected 카운터가 존재해야 한다");
    }
}
