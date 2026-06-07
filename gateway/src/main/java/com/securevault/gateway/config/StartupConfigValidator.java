package com.securevault.gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Faza 12 — validacija konfiguracije gateway-a na startu (fail-fast).
 *
 * <p>Gateway prijavljuje sigurnosne događaje backendu preko {@code /internal/**} sa deljenim
 * {@code INTERNAL_TOKEN}-om. Token ne sme biti prazan (uvek greška); u <b>produkciji</b>
 * ({@code prod} profil) nesigurna dev podrazumevana vrednost obara start, a u dev-u je samo
 * upozorenje. Logika je u statičkom {@link #validate} radi testiranja bez dizanja konteksta.
 */
@Component
public class StartupConfigValidator implements InitializingBean {

    private static final Logger log = LoggerFactory.getLogger(StartupConfigValidator.class);

    private final Environment environment;
    private final GatewayProperties gatewayProperties;

    public StartupConfigValidator(Environment environment, GatewayProperties gatewayProperties) {
        this.environment = environment;
        this.gatewayProperties = gatewayProperties;
    }

    @Override
    public void afterPropertiesSet() {
        boolean prod = isProdProfile(environment.getActiveProfiles());
        Outcome outcome = validate(prod, gatewayProperties.getInternalToken(),
                gatewayProperties.getBackendUri());

        outcome.warnings().forEach(w -> log.warn("[config] {}", w));

        if (!outcome.errors().isEmpty()) {
            throw new IllegalStateException(
                    "Neispravna/nesigurna konfiguracija — gateway neće biti pokrenut:"
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

    /** Čista (testabilna) validacija. */
    static Outcome validate(boolean prod, String internalToken, String backendUri) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        if (isBlank(internalToken)) {
            errors.add("app.internal-token (INTERNAL_TOKEN) nije postavljen.");
        }
        if (isBlank(backendUri)) {
            errors.add("app.backend-uri (BACKEND_URI) nije postavljen.");
        }

        if (isInsecureDefault(internalToken)) {
            String msg = "INTERNAL_TOKEN koristi nesigurnu dev podrazumevanu vrednost.";
            if (prod) {
                errors.add(msg);
            } else {
                warnings.add(msg);
            }
        }
        return new Outcome(errors, warnings);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

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
