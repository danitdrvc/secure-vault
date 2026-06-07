package com.securevault.honeypot.web;

import com.securevault.honeypot.repository.SecurityEventRepository;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static com.securevault.honeypot.web.InternalSecurityEventController.INTERNAL_TOKEN_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Faza 9: interni endpoint kojim gateway prijavljuje sigurnosne događaje
 * ({@code POST /internal/security-events}). Token-guarded — bez/sa pogrešnim
 * {@code X-Internal-Token} → {@code 401}; sa tačnim → {@code 201} i red u {@code security_event}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@AutoConfigureEmbeddedDatabase(provider = AutoConfigureEmbeddedDatabase.DatabaseProvider.ZONKY)
@TestPropertySource(properties = {
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.flyway.enabled=true",
        "spring.flyway.locations=classpath:db/migration",
        "app.internal.token=test-internal-token"
})
class InternalSecurityEventTest {

    private static final String VALID_TOKEN = "test-internal-token";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Test
    void validTokenCreatesSecurityEventRow() throws Exception {
        long before = securityEventRepository.findByTypeOrderByCreatedAtDesc("IP_BLOCKED").size();

        mockMvc.perform(post("/internal/security-events")
                        .header(INTERNAL_TOKEN_HEADER, VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"type\":\"IP_BLOCKED\",\"ip\":\"203.0.113.7\","
                                + "\"detail\":\"{\\\"reason\\\":\\\"FAILED_LOGIN\\\"}\"}"))
                .andExpect(status().isCreated());

        var events = securityEventRepository.findByTypeOrderByCreatedAtDesc("IP_BLOCKED");
        assertThat(events).hasSize((int) before + 1);
        assertThat(events.get(0).getIp()).isEqualTo("203.0.113.7");
        assertThat(events.get(0).getDetail()).contains("FAILED_LOGIN");
    }

    @Test
    void missingTokenIsRejected() throws Exception {
        long before = securityEventRepository.count();

        mockMvc.perform(post("/internal/security-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"type\":\"IP_BLOCKED\",\"ip\":\"203.0.113.7\"}"))
                .andExpect(status().isUnauthorized());

        assertThat(securityEventRepository.count()).isEqualTo(before);
    }

    @Test
    void wrongTokenIsRejected() throws Exception {
        long before = securityEventRepository.count();

        mockMvc.perform(post("/internal/security-events")
                        .header(INTERNAL_TOKEN_HEADER, "wrong-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"type\":\"IP_BLOCKED\",\"ip\":\"203.0.113.7\"}"))
                .andExpect(status().isUnauthorized());

        assertThat(securityEventRepository.count()).isEqualTo(before);
    }

    @Test
    void blankTypeIsRejectedAsValidationError() throws Exception {
        mockMvc.perform(post("/internal/security-events")
                        .header(INTERNAL_TOKEN_HEADER, VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"type\":\"\",\"ip\":\"203.0.113.7\"}"))
                .andExpect(status().isBadRequest());
    }
}
