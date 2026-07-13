package com.aegis;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Leaderboard route (R6): fields + score present and well-typed. */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "aegis.hs256.secret=test-secret-test-secret-test-secret-1234567890"
})
class ArenaStatusControllerTest {

    @Autowired private MockMvc mvc;

    @Test
    void arenaReturnsLeaderboardWithStateAndScore() throws Exception {
        mvc.perform(get("/admin/arena"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.leaderboard", hasSize(3)))
                .andExpect(jsonPath("$.leaderboard[0].algorithm").isNotEmpty())
                .andExpect(jsonPath("$.leaderboard[0].state").isNotEmpty())
                .andExpect(jsonPath("$.leaderboard[0].score").isNumber())
                .andExpect(jsonPath("$.leaderboard[0].avgVerifyMs").isNumber())
                .andExpect(jsonPath("$.leaderboard[0].memoryPressure").isNumber());
    }
}
