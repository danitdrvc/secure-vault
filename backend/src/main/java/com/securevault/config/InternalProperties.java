package com.securevault.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Konfiguracija interne (server-to-server) komunikacije vezana na {@code app.internal.*}.
 *
 * <p>Gateway (Faza 9) prijavljuje sigurnosne događaje backendu preko {@code /internal/**}
 * ruta koje NISU izložene kroz gateway ({@code /api/**} StripPrefix ih ne pokriva). Pristup
 * štiti deljeni token u {@code X-Internal-Token} zaglavlju — backend odbija svaki zahtev bez
 * tačnog tokena ({@code 401}).
 */
@ConfigurationProperties(prefix = "app.internal")
public class InternalProperties {

    /** Deljeni token između gateway-a i backenda za interne pozive. */
    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
