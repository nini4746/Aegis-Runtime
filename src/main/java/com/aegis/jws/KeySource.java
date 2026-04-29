package com.aegis.jws;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.Optional;

/**
 * Abstracts the source of cryptographic keys used for JWS verification.
 * Implementations may load from local files, JWKS endpoints, KMS, HashiCorp Vault, etc.
 *
 * Invariants:
 *  - hs256Secret() must produce a key of >= 32 bytes
 *  - asymKeys(alg) returns Optional.empty() if the algorithm is not supported by this source
 *  - implementations must be thread-safe — invoked once at startup but key rotation
 *    implementations may be queried periodically
 */
public interface KeySource {

    /** Stable name shown in metrics/logs. */
    String name();

    /** HMAC secret used for HS256. Must be >= 32 bytes. */
    SecretKey hs256Secret();

    /**
     * Asymmetric key pair for the given algorithm.
     * @param algorithm e.g. "RS256", "ES256"
     * @return KeyPair if supported, Optional.empty() otherwise
     */
    Optional<KeyPair> asymKeys(String algorithm);
}
