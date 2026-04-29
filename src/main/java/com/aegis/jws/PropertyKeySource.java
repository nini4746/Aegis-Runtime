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
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

/**
 * Default KeySource that reads HMAC secret from `aegis.hs256.secret` and asymmetric
 * key paths (PEM) from `aegis.{rs256,es256}.{private,public}-key-path`. Falls back
 * to ephemeral generation with a WARN log when paths are not configured.
 */
@Component
public class PropertyKeySource implements KeySource {

    private static final Logger log = LoggerFactory.getLogger(PropertyKeySource.class);
    private static final int MIN_HS256_SECRET_BYTES = 32;

    private final SecretKey hs256;
    private final KeyPair rsa;
    private final KeyPair ec;

    public PropertyKeySource(@Value("${aegis.hs256.secret:}") String hsSecret,
                             @Value("${aegis.rs256.private-key-path:}") String rsaPrivPath,
                             @Value("${aegis.rs256.public-key-path:}") String rsaPubPath,
                             @Value("${aegis.es256.private-key-path:}") String ecPrivPath,
                             @Value("${aegis.es256.public-key-path:}") String ecPubPath) {
        this.hs256 = buildHs256(hsSecret);
        this.rsa = loadOrGenerateRsa(rsaPrivPath, rsaPubPath);
        this.ec = loadOrGenerateEc(ecPrivPath, ecPubPath);
    }

    @Override public String name() { return "property"; }

    @Override public SecretKey hs256Secret() { return hs256; }

    @Override
    public Optional<KeyPair> asymKeys(String algorithm) {
        return switch (algorithm) {
            case "RS256" -> Optional.of(rsa);
            case "ES256" -> Optional.of(ec);
            default -> Optional.empty();
        };
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

    private KeyPair loadOrGenerateRsa(String privPath, String pubPath) {
        if (!privPath.isBlank() && !pubPath.isBlank()) {
            try {
                return new KeyPair(readPublicKey("RSA", pubPath), readPrivateKey("RSA", privPath));
            } catch (Exception e) {
                throw new IllegalStateException("failed to load RSA keys from " + privPath + " / " + pubPath, e);
            }
        }
        log.warn("RS256 key paths not configured; generating EPHEMERAL RSA key (NOT SUITABLE FOR PRODUCTION)");
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            return g.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA unavailable", e);
        }
    }

    private KeyPair loadOrGenerateEc(String privPath, String pubPath) {
        if (!privPath.isBlank() && !pubPath.isBlank()) {
            try {
                return new KeyPair(readPublicKey("EC", pubPath), readPrivateKey("EC", privPath));
            } catch (Exception e) {
                throw new IllegalStateException("failed to load EC keys from " + privPath + " / " + pubPath, e);
            }
        }
        log.warn("ES256 key paths not configured; generating EPHEMERAL EC key (NOT SUITABLE FOR PRODUCTION)");
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            return g.generateKeyPair();
        } catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("EC unavailable", e);
        }
    }

    private static java.security.PrivateKey readPrivateKey(String alg, String path) throws IOException, java.security.spec.InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] der = decodePem(Files.readString(Path.of(path)));
        return KeyFactory.getInstance(alg).generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static java.security.PublicKey readPublicKey(String alg, String path) throws IOException, java.security.spec.InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] der = decodePem(Files.readString(Path.of(path)));
        return KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(der));
    }

    private static byte[] decodePem(String pem) {
        String body = pem.replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(body);
    }
}
