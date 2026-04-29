package com.aegis.jws;

import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Builds AlgorithmWorker instances backed by a pluggable KeySource. Decoupling key
 * sourcing from the worker registry lets us swap in JWKS, KMS, Vault, or rotation
 * implementations without touching verification logic.
 */
@Component
public class WorkerRegistry {

    private final Map<String, AlgorithmWorker> workers = new ConcurrentHashMap<>();
    private final SecretKey hs256Secret;
    private final PrivateKey rsaPrivate;
    private final PrivateKey ecPrivate;
    private final PublicKey rsaPublic;
    private final PublicKey ecPublic;

    public WorkerRegistry(KeySource keySource) {
        this.hs256Secret = keySource.hs256Secret();
        workers.put("HS256", new AlgorithmWorker("HS256", hs256Secret));

        KeyPair rsa = keySource.asymKeys("RS256")
                .orElseThrow(() -> new IllegalStateException("KeySource " + keySource.name() + " does not support RS256"));
        this.rsaPrivate = rsa.getPrivate();
        this.rsaPublic = rsa.getPublic();
        workers.put("RS256", new AlgorithmWorker("RS256", rsa.getPublic()));

        KeyPair ec = keySource.asymKeys("ES256")
                .orElseThrow(() -> new IllegalStateException("KeySource " + keySource.name() + " does not support ES256"));
        this.ecPrivate = ec.getPrivate();
        this.ecPublic = ec.getPublic();
        workers.put("ES256", new AlgorithmWorker("ES256", ec.getPublic()));
    }

    public AlgorithmWorker forAlgorithm(String alg) {
        return workers.get(alg);
    }

    public SecretKey hs256Secret() { return hs256Secret; }
    public PrivateKey rsaPrivate() { return rsaPrivate; }
    public PrivateKey ecPrivate() { return ecPrivate; }
    public PublicKey rsaPublic() { return rsaPublic; }
    public PublicKey ecPublic() { return ecPublic; }
}
