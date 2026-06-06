package com.securevault.health;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.securevault.config.AuthProperties;
import com.securevault.config.SecurityConfig;
import com.securevault.security.JwtService;
import com.securevault.security.RestAuthenticationEntryPoint;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Učitava STVARNU security konfiguraciju (Faza 4) da bi se /health proverio kroz pravi
 * filter chain — gde je javno (permitAll), za razliku od podrazumevane Boot security koja
 * bi sve zaključala. Importuju se beanovi koje {@code SecurityConfig} zahteva.
 */
@WebMvcTest(HealthController.class)
@Import({SecurityConfig.class, JwtService.class, RestAuthenticationEntryPoint.class})
@EnableConfigurationProperties(AuthProperties.class)
class HealthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void healthReturnsStatusOk() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"));
    }
}
