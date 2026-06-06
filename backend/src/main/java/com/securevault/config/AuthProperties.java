package com.securevault.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Konfiguracija autentikacije vezana na {@code app.auth.*} (vidi application.yml).
 *
 * <p>Sadrži SAMO tajne i ne-političke parametre. Vremenski TTL-ovi (access / refresh /
 * apsolutni cap sesije) NISU ovde — oni dolaze iz aktivne {@code security_policy} koju
 * admin menja u Fazi 8, pa ih čita {@code TokenService} u runtime-u.
 */
@ConfigurationProperties(prefix = "app.auth")
public class AuthProperties {

    /** HS256 tajna za potpis JWT-a. Mora biti >= 32 bajta. */
    private String jwtSecret;

    /** {@code iss} claim na izdatim tokenima. */
    private String jwtIssuer = "secure-vault";

    /** Server-side ključ kojim se TOTP tajne šifruju u bazi (svodi se na 32B AES ključ). */
    private String serverKmsKey;

    /** Trajanje privremenog MFA tiketa između login koraka (sekunde). */
    private int mfaTicketTtlSec = 300;

    /** Secure flag na sesijskim kolačićima (false za lokalni http dev). */
    private boolean cookieSecure = false;

    public String getJwtSecret() {
        return jwtSecret;
    }

    public void setJwtSecret(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    public String getJwtIssuer() {
        return jwtIssuer;
    }

    public void setJwtIssuer(String jwtIssuer) {
        this.jwtIssuer = jwtIssuer;
    }

    public String getServerKmsKey() {
        return serverKmsKey;
    }

    public void setServerKmsKey(String serverKmsKey) {
        this.serverKmsKey = serverKmsKey;
    }

    public int getMfaTicketTtlSec() {
        return mfaTicketTtlSec;
    }

    public void setMfaTicketTtlSec(int mfaTicketTtlSec) {
        this.mfaTicketTtlSec = mfaTicketTtlSec;
    }

    public boolean isCookieSecure() {
        return cookieSecure;
    }

    public void setCookieSecure(boolean cookieSecure) {
        this.cookieSecure = cookieSecure;
    }
}
