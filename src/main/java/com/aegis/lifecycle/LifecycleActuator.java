package com.aegis.lifecycle;

import com.aegis.jws.TokenVerificationCache;
import org.springframework.stereotype.Component;

/**
 * Applies a decided Transition and performs its side effects (R4, D3):
 *  - kill (-> DEAD): invalidate that algorithm's verification cache entries and set the
 *    admission-reject flag (state == DEAD). Key material is NOT touched.
 *  - recover (-> ACTIVE): nothing extra; admission is re-enabled the moment state leaves DEAD.
 */
@Component
public class LifecycleActuator {

    private final LifecycleRegistry registry;
    private final TokenVerificationCache cache;

    public LifecycleActuator(LifecycleRegistry registry, TokenVerificationCache cache) {
        this.registry = registry;
        this.cache = cache;
    }

    public boolean apply(Transition t) {
        AlgorithmLifecycle lc = registry.lifecycle(t.algorithm());
        if (lc == null) return false;
        boolean applied = lc.transitionTo(t.to(), t.reason());
        if (applied && t.to() == AlgorithmState.DEAD) {
            cache.invalidateAlgorithm(t.algorithm());
        }
        return applied;
    }
}
