package com.aegis;

import com.aegis.lifecycle.AlgorithmLifecycle;
import com.aegis.lifecycle.AlgorithmState;
import com.aegis.lifecycle.KillReason;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

/** State-machine edge guard + kill-reason preservation (R1), driven by a fake nanos clock (D5). */
class AlgorithmLifecycleTest {

    @Test
    void legal_edges_apply_illegal_edges_ignored() {
        AtomicLong now = new AtomicLong(0);
        AlgorithmLifecycle lc = new AlgorithmLifecycle("RS256", now::get);

        assertEquals(AlgorithmState.ACTIVE, lc.state());
        // illegal: ACTIVE -> DEAD directly
        assertFalse(lc.transitionTo(AlgorithmState.DEAD, KillReason.MEMORY_PRESSURE));
        assertEquals(AlgorithmState.ACTIVE, lc.state());

        assertTrue(lc.transitionTo(AlgorithmState.THROTTLED, null));
        assertEquals(AlgorithmState.THROTTLED, lc.state());
        assertFalse(lc.admissionRejected());

        assertTrue(lc.transitionTo(AlgorithmState.DEAD, KillReason.MEMORY_PRESSURE));
        assertEquals(AlgorithmState.DEAD, lc.state());
        assertTrue(lc.admissionRejected());
        assertEquals(KillReason.MEMORY_PRESSURE, lc.lastKillReason());

        // illegal: DEAD -> THROTTLED directly
        assertFalse(lc.transitionTo(AlgorithmState.THROTTLED, null));
        assertEquals(AlgorithmState.DEAD, lc.state());
    }

    @Test
    void state_entered_nanos_tracks_fake_clock() {
        AtomicLong now = new AtomicLong(1000);
        AlgorithmLifecycle lc = new AlgorithmLifecycle("ES256", now::get);
        assertEquals(1000, lc.stateEnteredNanos());
        now.set(7777);
        lc.transitionTo(AlgorithmState.THROTTLED, null);
        assertEquals(7777, lc.stateEnteredNanos());
    }
}
