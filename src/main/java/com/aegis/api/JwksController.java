package com.aegis.api;

import com.aegis.jws.WorkerRegistry;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
public class JwksController {

    private final WorkerRegistry workers;

    public JwksController(WorkerRegistry workers) {
        this.workers = workers;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        List<Map<String, Object>> keys = new ArrayList<>();
        keys.add(rsaKey(workers.rsaPublic()));
        keys.add(ecKey(workers.ecPublic()));
        return Map.of("keys", keys);
    }

    private Map<String, Object> rsaKey(PublicKey pub) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("alg", "RS256");
        jwk.put("use", "sig");
        jwk.put("kid", "rs256-current");
        if (pub instanceof RSAPublicKey rsa) {
            jwk.put("n", base64UrlNoPad(rsa.getModulus().toByteArray()));
            jwk.put("e", base64UrlNoPad(rsa.getPublicExponent().toByteArray()));
        }
        return jwk;
    }

    private Map<String, Object> ecKey(PublicKey pub) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("alg", "ES256");
        jwk.put("crv", "P-256");
        jwk.put("use", "sig");
        jwk.put("kid", "es256-current");
        if (pub instanceof ECPublicKey ec) {
            jwk.put("x", base64UrlNoPad(ec.getW().getAffineX().toByteArray()));
            jwk.put("y", base64UrlNoPad(ec.getW().getAffineY().toByteArray()));
        }
        return jwk;
    }

    private static String base64UrlNoPad(byte[] bytes) {
        // RFC 7518 §6.3.1.1 specifies unpadded big-endian bytes; trim leading sign byte if present
        int start = 0;
        if (bytes.length > 1 && bytes[0] == 0) start = 1;
        byte[] trimmed = new byte[bytes.length - start];
        System.arraycopy(bytes, start, trimmed, 0, trimmed.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(trimmed);
    }
}
