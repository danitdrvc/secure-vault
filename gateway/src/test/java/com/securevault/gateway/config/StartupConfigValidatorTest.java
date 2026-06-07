package com.securevault.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.securevault.gateway.config.StartupConfigValidator.Outcome;
import org.junit.jupiter.api.Test;

/**
 * Acceptance (Faza 12): validacija konfiguracije gateway-a na startu.
 *
 * <p>Prazan {@code INTERNAL_TOKEN}/{@code BACKEND_URI} je greška uvek; nesigurna dev
 * podrazumevana vrednost je upozorenje u dev-u, ali greška u {@code prod} profilu.
 */
class StartupConfigValidatorTest {

    private static final String BACKEND = "http://localhost:8081";
    private static final String DEV_TOKEN = "dev-only-insecure-internal-token-change-me";
    private static final String STRONG_TOKEN = "Zq8w7e6r5t4y3u2i1o0p-internal-shared";

    @Test
    void prazanTokenJeGreska() {
        Outcome outcome = StartupConfigValidator.validate(false, "   ", BACKEND);

        assertThat(outcome.errors()).isNotEmpty();
    }

    @Test
    void devPodrazumevaniTokenJeUpozorenjeUDev() {
        Outcome outcome = StartupConfigValidator.validate(false, DEV_TOKEN, BACKEND);

        assertThat(outcome.errors()).isEmpty();
        assertThat(outcome.warnings()).isNotEmpty();
    }

    @Test
    void devPodrazumevaniTokenJeGreskaUProd() {
        Outcome outcome = StartupConfigValidator.validate(true, DEV_TOKEN, BACKEND);

        assertThat(outcome.errors()).isNotEmpty();
    }

    @Test
    void jakTokenUProdProlazi() {
        Outcome outcome = StartupConfigValidator.validate(true, STRONG_TOKEN, BACKEND);

        assertThat(outcome.errors()).isEmpty();
        assertThat(outcome.warnings()).isEmpty();
    }
}
