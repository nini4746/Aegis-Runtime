package com.aegis.jws;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Base64;

public final class JwsHeaderInspector {

    private static final ObjectMapper OM = new ObjectMapper();

    private JwsHeaderInspector() {}

    public static String algorithm(String token) {
        if (token == null) return null;
        int dot = token.indexOf('.');
        if (dot <= 0) return null;
        try {
            byte[] headerBytes = Base64.getUrlDecoder().decode(token.substring(0, dot));
            JsonNode node = OM.readTree(headerBytes);
            JsonNode alg = node.get("alg");
            return alg == null ? null : alg.asText();
        } catch (Exception e) {
            return null;
        }
    }
}
