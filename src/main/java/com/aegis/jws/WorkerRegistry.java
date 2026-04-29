package com.aegis.jws;

import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class WorkerRegistry {

    private static final Logger log = LoggerFactory.getLogger(WorkerRegistry.class);
    private static final int MIN_HS256_SECRET_BYTES = 32;

    private final Map<String, AlgorithmWorker> workers = new ConcurrentHashMap<>();
    private final SecretKey hs256Secret;
    private final PrivateKey rsaPrivate;
    private final PrivateKey ecPrivate;
    private final PublicKey rsaPublic;
    private final PublicKey ecPublic;

    public WorkerRegistry(@Value("${aegis.hs256.secret:}") String hsSecret,
                          @Value("${aegis.rs256.private-key-path:}") String rsaPrivPath,
                          @Value("${aegis.rs256.public-key-path:}") String rsaPubPath,
                          @Value("${aegis.es256.private-key-path:}") String ecPrivPath,
                          @Value("${aegis.es256.public-key-path:}") String ecPubPath) {
        this.hs256Secret = buildHs256(hsSecret);
        workers.put("HS256", new AlgorithmWorker("HS256", hs256Secret));

        AsymKeys rsa = loadOrGenerateRsa(rsaPrivPath, rsaPubPath);
        this.rsaPrivate = rsa.priv;
        this.rsaPublic = rsa.pub;
        workers.put("RS256", new AlgorithmWorker("RS256", rsa.pub));

        AsymKeys ec = loadOrGenerateEc(ecPrivPath, ecPubPath);
        this.ecPrivate = ec.priv;
        this.ecPublic = ec.pub;
        workers.put("ES256", new AlgorithmWorker("ES256", ec.pub));
    }

    private static SecretKey buildHs256(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException(
                    "aegis.hs256.secret (HS256_SECRET) is not set; refusing to start without an explicit HMAC secret");
        }
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < MIN_HS256_SECRET_BYTES) {
            throw new IllegalStateException(
                    "aegis.hs256.secret must be at least " + MIN_HS256_SECRET_BYTES + " bytes; got " + bytes.length);
        }
        return Keys.hmacShaKeyFor(bytes);
    }

    private AsymKeys loadOrGenerateRsa(String privPath, String pubPath) {
        if (!privPath.isBlank() && !pubPath.isBlank()) {
            try {
                PrivateKey priv = readPrivateKey("RSA", privPath);
                PublicKey pub = readPublicKey("RSA", pubPath);
                log.info("loaded RSA key pair from disk");
                return new AsymKeys(priv, pub);
            } catch (Exception e) {
                throw new IllegalStateException("failed to load RSA keys from " + privPath + " / " + pubPath, e);
            }
        }
        log.warn("RS256 key paths not configured; generating EPHEMERAL RSA key (NOT SUITABLE FOR PRODUCTION)");
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            KeyPair p = g.generateKeyPair();
            return new AsymKeys(p.getPrivate(), p.getPublic());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA unavailable", e);
        }
    }

    private AsymKeys loadOrGenerateEc(String privPath, String pubPath) {
        if (!privPath.isBlank() && !pubPath.isBlank()) {
            try {
                PrivateKey priv = readPrivateKey("EC", privPath);
                PublicKey pub = readPublicKey("EC", pubPath);
                log.info("loaded EC key pair from disk");
                return new AsymKeys(priv, pub);
            } catch (Exception e) {
                throw new IllegalStateException("failed to load EC keys from " + privPath + " / " + pubPath, e);
            }
        }
        log.warn("ES256 key paths not configured; generating EPHEMERAL EC key (NOT SUITABLE FOR PRODUCTION)");
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair p = g.generateKeyPair();
            return new AsymKeys(p.getPrivate(), p.getPublic());
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("EC unavailable", e);
        }
    }

    private static PrivateKey readPrivateKey(String alg, String path) throws IOException, java.security.spec.InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] der = decodePem(Files.readString(Path.of(path)));
        return KeyFactory.getInstance(alg).generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static PublicKey readPublicKey(String alg, String path) throws IOException, java.security.spec.InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] der = decodePem(Files.readString(Path.of(path)));
        return KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(der));
    }

    private static byte[] decodePem(String pem) {
        String body = pem.replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(body);
    }

    public AlgorithmWorker forAlgorithm(String alg) {
        return workers.get(alg);
    }

    public SecretKey hs256Secret() { return hs256Secret; }
    public PrivateKey rsaPrivate() { return rsaPrivate; }
    public PrivateKey ecPrivate() { return ecPrivate; }
    public PublicKey rsaPublic() { return rsaPublic; }
    public PublicKey ecPublic() { return ecPublic; }

    private record AsymKeys(PrivateKey priv, PublicKey pub) {}
}
