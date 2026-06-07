package com.securevault.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Faza 12 — validacija konfiguracije/env varijabli na startu (fail-fast).
 *
 * <p>Proverava da kritične tajne nisu prazne i da su dovoljno jake. U <b>produkciji</b>
 * (aktivan {@code prod} profil) nesigurne podrazumevane (dev) vrednosti su GREŠKA i app
 * odbija da se podigne; u dev okruženju su samo UPOZORENJE (da lokalno pokretanje radi
 * bez podešavanja). Time se sprečava da projekat slučajno ode u produkciju sa dev tajnama.
 *
 * <p>Tvrde provere (uvek greška, bez obzira na profil): {@code JWT_SECRET} mora postojati i
 * imati ≥ 32 bajta (HS256 zahtev iz {@code jjwt}); {@code SERVER_KMS_KEY} i {@code INTERNAL_TOKEN}
 * ne smeju biti prazni. Logika je izdvojena u statički {@link #validate} radi testiranja bez
 * dizanja konteksta.
 */
@Component
public class StartupConfigValidator implements InitializingBean {

    private static final Logger log = LoggerFactory.getLogger(StartupConfigValidator.class);

    /** Minimalna dužina HS256 tajne u bajtovima (256 bita). */
    static final int MIN_JWT_SECRET_BYTES = 32;

    private final Environment environment;
    private final AuthProperties authProperties;
    private final InternalProperties internalProperties;
    private final String datasourcePassword;

    public StartupConfigValidator(Environment environment,
                                  AuthProperties authProperties,
                                  InternalProperties internalProperties,
                                  @Value("${spring.datasource.password:}") String datasourcePassword) {
        this.environment = environment;
        this.authProperties = authProperties;
        this.internalProperties = internalProperties;
        this.datasourcePassword = datasourcePassword;
    }

    @Override
    public void afterPropertiesSet() {
        boolean prod = isProdProfile(environment.getActiveProfiles());
        Outcome outcome = validate(
                prod,
                authProperties.getJwtSecret(),
                authProperties.getServerKmsKey(),
                internalProperties.getToken(),
                authProperties.isCookieSecure(),
                datasourcePassword);

        outcome.warnings().forEach(w -> log.warn("[config] {}", w));

        if (!outcome.errors().isEmpty()) {
            throw new IllegalStateException(
                    "Neispravna/nesigurna konfiguracija — app neće biti pokrenut:"
                            + System.lineSeparator() + "  - "
                            + String.join(System.lineSeparator() + "  - ", outcome.errors()));
        }
        log.info("[config] Validacija konfiguracije prošla (profil={}, upozorenja={}).",
                prod ? "prod" : "dev", outcome.warnings().size());
    }

    static boolean isProdProfile(String[] activeProfiles) {
        if (activeProfiles == null) {
            return false;
        }
        for (String profile : activeProfiles) {
            if ("prod".equalsIgnoreCase(profile)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Čista (testabilna) validacija. Tvrde greške uvek obaraju start; nesigurne dev vrednosti
     * su greška u {@code prod}, inače upozorenje.
     */
    static Outcome validate(boolean prod,
                            String jwtSecret,
                            String serverKmsKey,
                            String internalToken,
                            boolean cookieSecure,
                            String datasourcePassword) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        // --- Tvrde provere (uvek greška) ---
        if (isBlank(jwtSecret)) {
            errors.add("app.auth.jwt-secret (JWT_SECRET) nije postavljen.");
        } else if (jwtSecret.getBytes(StandardCharsets.UTF_8).length < MIN_JWT_SECRET_BYTES) {
            errors.add("JWT_SECRET mora imati najmanje " + MIN_JWT_SECRET_BYTES
                    + " bajta (HS256); trenutno " + jwtSecret.getBytes(StandardCharsets.UTF_8).length + ".");
        }
        if (isBlank(serverKmsKey)) {
            errors.add("app.auth.server-kms-key (SERVER_KMS_KEY) nije postavljen.");
        }
        if (isBlank(internalToken)) {
            errors.add("app.internal.token (INTERNAL_TOKEN) nije postavljen.");
        }

        // --- Nesigurne dev vrednosti: greška u prod, upozorenje u dev ---
        List<String> insecure = new ArrayList<>();
        if (isInsecureDefault(jwtSecret)) {
            insecure.add("JWT_SECRET koristi nesigurnu dev podrazumevanu vrednost.");
        }
        if (isInsecureDefault(serverKmsKey)) {
            insecure.add("SERVER_KMS_KEY koristi nesigurnu dev podrazumevanu vrednost.");
        }
        if (isInsecureDefault(internalToken)) {
            insecure.add("INTERNAL_TOKEN koristi nesigurnu dev podrazumevanu vrednost.");
        }
        if ("vault".equals(datasourcePassword)) {
            insecure.add("POSTGRES_PASSWORD koristi podrazumevanu vrednost 'vault'.");
        }
        if (!cookieSecure) {
            insecure.add("APP_COOKIE_SECURE=false — sesijski kolačići se šalju bez Secure flega "
                    + "(prihvatljivo samo za lokalni http dev).");
        }

        if (prod) {
            errors.addAll(insecure);
        } else {
            warnings.addAll(insecure);
        }
        return new Outcome(errors, warnings);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /** Dev placeholderi iz application.yml / .env.example sadrže ove markere. */
    private static boolean isInsecureDefault(String value) {
        if (value == null) {
            return false;
        }
        return value.contains("dev-only-insecure") || value.contains("change-me");
    }

    /** Rezultat validacije: greške obaraju start, upozorenja se samo loguju. */
    record Outcome(List<String> errors, List<String> warnings) {
    }
}
