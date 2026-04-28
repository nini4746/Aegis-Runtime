package com.aegis.jws;

import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class WorkerRegistry {

    private final Map<String, AlgorithmWorker> workers = new ConcurrentHashMap<>();
    private final SecretKey hs256Secret;
    private final PrivateKey rsaPrivate;
    private final PrivateKey ecPrivate;

    public WorkerRegistry(@Value("${aegis.hs256.secret:dev-secret-please-change-this-key-1234567890}") String hsSecret) {
        this.hs256Secret = Keys.hmacShaKeyFor(hsSecret.getBytes(StandardCharsets.UTF_8));
        workers.put("HS256", new AlgorithmWorker("HS256", hs256Secret));

        try {
            KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
            rsaGen.initialize(2048);
            KeyPair rsa = rsaGen.generateKeyPair();
            this.rsaPrivate = rsa.getPrivate();
            workers.put("RS256", new AlgorithmWorker("RS256", rsa.getPublic()));

            KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
            ecGen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair ec = ecGen.generateKeyPair();
            this.ecPrivate = ec.getPrivate();
            workers.put("ES256", new AlgorithmWorker("ES256", ec.getPublic()));
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("could not init asym keys", e);
        }
    }

    public AlgorithmWorker forAlgorithm(String alg) {
        return workers.get(alg);
    }

    public SecretKey hs256Secret() { return hs256Secret; }
    public PrivateKey rsaPrivate() { return rsaPrivate; }
    public PrivateKey ecPrivate() { return ecPrivate; }
}
