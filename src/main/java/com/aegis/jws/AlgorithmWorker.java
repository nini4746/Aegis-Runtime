package com.aegis.jws;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtParser;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PublicKey;
import java.util.concurrent.atomic.AtomicLong;

public class AlgorithmWorker {

    private final String name;
    private final Key verifyKey;
    private final AtomicLong totalNanos = new AtomicLong();
    private final AtomicLong totalCount = new AtomicLong();

    public AlgorithmWorker(String name, Key verifyKey) {
        this.name = name;
        this.verifyKey = verifyKey;
    }

    public String name() { return name; }

    public Jws<Claims> verify(String token) {
        long start = System.nanoTime();
        try {
            JwtParser parser;
            if (verifyKey instanceof SecretKey sk) {
                parser = Jwts.parser().verifyWith(sk).build();
            } else if (verifyKey instanceof PublicKey pk) {
                parser = Jwts.parser().verifyWith(pk).build();
            } else {
                throw new IllegalStateException("unsupported key kind");
            }
            return parser.parseSignedClaims(token);
        } finally {
            long delta = System.nanoTime() - start;
            totalNanos.addAndGet(delta);
            totalCount.incrementAndGet();
        }
    }

    public double avgVerifyTimeMs() {
        long c = totalCount.get();
        if (c == 0) return 1.0;
        return (totalNanos.get() / 1_000_000.0) / c;
    }
}
