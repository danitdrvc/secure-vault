package com.securevault.config;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.securevault.health.HealthController;
import com.securevault.security.JwtService;
import com.securevault.security.RestAuthenticationEntryPoint;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Acceptance (Faza 12): svaki odgovor — i uspešan (200) i odbijen (401) — nosi sigurnosna
 * HTTP zaglavlja iz {@link SecurityConfig}. Učitava STVARNI security filter chain (kao
 * {@code HealthControllerTest}) da bi zaglavlja došla iz prave konfiguracije.
 */
@WebMvcTest(HealthController.class)
@Import({SecurityConfig.class, JwtService.class, RestAuthenticationEntryPoint.class})
@EnableConfigurationProperties(AuthProperties.class)
class SecurityHeadersTest {

    private static final String CSP =
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
    private static final String PERMISSIONS =
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void uspesanOdgovorNosiSvaSigurnosnaZaglavlja() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("Content-Security-Policy", CSP))
                .andExpect(header().string("Permissions-Policy", PERMISSIONS));
    }

    @Test
    void odbijenZahtevBezSesijeTakodjeNosiZaglavlja() throws Exception {
        // Zaštićena ruta bez tokena → 401 iz entry point-a; sigurnosna zaglavlja MORAJU ostati.
        mockMvc.perform(get("/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Content-Security-Policy", CSP));
    }
}
