package com.securevault.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.securevault.config.StartupConfigValidator.Outcome;
import org.junit.jupiter.api.Test;

/**
 * Acceptance (Faza 12): validacija konfiguracije na startu.
 *
 * <p>Dev podrazumevane (nesigurne) vrednosti su samo UPOZORENJE u dev-u, ali GREŠKA u
 * {@code prod} profilu (fail-fast). Tvrde provere (prazan/prekratak {@code JWT_SECRET},
 * prazne tajne) su greška uvek.
 */
class StartupConfigValidatorTest {

    // Dev placeholderi (poklapaju se sa application.yml / .env.example markerima).
    private static final String DEV_JWT = "dev-only-insecure-jwt-secret-change-me-0123456789abcdef";
    private static final String DEV_KMS = "dev-only-insecure-server-kms-key-change-me";
    private static final String DEV_TOKEN = "dev-only-insecure-internal-token-change-me";

    // Jake vrednosti (≥ 32 bajta za JWT, bez "change-me"/"dev-only-insecure" markera).
    private static final String STRONG_JWT = "Yk9p2sL!q7wZ3xR8tV1nB6mC4dF0gH5jK-strong-secret";
    private static final String STRONG_KMS = "Yk9p2sLq7wZ3xR8tV1nB6mC4dF0gH5jK";
    private static final String STRONG_TOKEN = "Zq8w7e6r5t4y3u2i1o0p-internal-shared";

    @Test
    void devPodrazumevaneVrednostiSuSamoUpozorenja() {
        Outcome outcome = StartupConfigValidator.validate(
                false, DEV_JWT, DEV_KMS, DEV_TOKEN, false, "vault");

        assertThat(outcome.errors()).isEmpty();
        // JWT, KMS, INTERNAL_TOKEN, DB lozinka, cookie-secure → 5 upozorenja.
        assertThat(outcome.warnings()).hasSize(5);
    }

    @Test
    void istinNesigurneVrednostiUProdProfiluSuGreske() {
        Outcome outcome = StartupConfigValidator.validate(
                true, DEV_JWT, DEV_KMS, DEV_TOKEN, false, "vault");

        assertThat(outcome.warnings()).isEmpty();
        assertThat(outcome.errors()).hasSize(5);
    }

    @Test
    void jakeVrednostiUProdProlazeBezGresakaIUpozorenja() {
        Outcome outcome = StartupConfigValidator.validate(
                true, STRONG_JWT, STRONG_KMS, STRONG_TOKEN, true, "Str0ng-DB-pass!");

        assertThat(outcome.errors()).isEmpty();
        assertThat(outcome.warnings()).isEmpty();
    }

    @Test
    void prekratakJwtSecretJeUvekGreska() {
        Outcome outcome = StartupConfigValidator.validate(
                false, "too-short", STRONG_KMS, STRONG_TOKEN, true, "Str0ng-DB-pass!");

        assertThat(outcome.errors()).anyMatch(e -> e.contains("32"));
    }

    @Test
    void prazneObaveneTajneSuGreske() {
        Outcome outcome = StartupConfigValidator.validate(
                false, "   ", "", null, true, "Str0ng-DB-pass!");

        // JWT prazan + KMS prazan + INTERNAL_TOKEN prazan = 3 tvrde greške.
        assertThat(outcome.errors()).hasSize(3);
    }
}
