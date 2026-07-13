package com.aegis.lifecycle;

import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * Holds one AlgorithmLifecycle per algorithm (R3). Keys mirror WorkerRegistry
 * (HS256/RS256/ES256). All lifecycles share the injected nanos seam (D5).
 */
@Component
public class LifecycleRegistry {

    private final Map<String, AlgorithmLifecycle> lifecycles = new LinkedHashMap<>();

    public LifecycleRegistry(LongSupplier nanos) {
        for (String alg : new String[]{"HS256", "RS256", "ES256"}) {
            lifecycles.put(alg, new AlgorithmLifecycle(alg, nanos));
        }
    }

    public AlgorithmLifecycle lifecycle(String algorithm) {
        return lifecycles.get(algorithm);
    }

    public AlgorithmState stateOf(String algorithm) {
        AlgorithmLifecycle lc = lifecycles.get(algorithm);
        return lc == null ? null : lc.state();
    }

    public Set<String> algorithms() {
        return lifecycles.keySet();
    }
}
