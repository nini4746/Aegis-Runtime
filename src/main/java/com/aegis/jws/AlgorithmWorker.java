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

    private static final double EWMA_ALPHA = 0.1;
    private static final double DEFAULT_AVG_MS = 1.0;

    private final String name;
    private final Key verifyKey;
    private final AtomicLong avgNanosBits = new AtomicLong(Double.doubleToRawLongBits(-1.0));

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
            updateEwma(System.nanoTime() - start);
        }
    }

    private void updateEwma(long sampleNanos) {
        while (true) {
            long bits = avgNanosBits.get();
            double prev = Double.longBitsToDouble(bits);
            double next = prev < 0 ? sampleNanos : EWMA_ALPHA * sampleNanos + (1 - EWMA_ALPHA) * prev;
            if (avgNanosBits.compareAndSet(bits, Double.doubleToRawLongBits(next))) return;
        }
    }

    public double avgVerifyTimeMs() {
        double avg = Double.longBitsToDouble(avgNanosBits.get());
        if (avg < 0) return DEFAULT_AVG_MS;
        return avg / 1_000_000.0;
    }
}
