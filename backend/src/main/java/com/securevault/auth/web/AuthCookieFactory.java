package com.securevault.auth.web;

import com.securevault.config.AuthProperties;
import com.securevault.security.JwtCookieAuthenticationFilter;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

/**
 * Pravi sesijske kolačiće sa {@code HttpOnly; Secure; SameSite=Strict} flegovima.
 *
 * <p>{@code HttpOnly} sprečava čitanje tokena iz JS-a (XSS), {@code SameSite=Strict} blokira
 * slanje kolačića na cross-site zahtevima (CSRF zaštita), a {@code Secure} ograničava na HTTPS
 * (u dev-u se gasi preko {@code app.auth.cookie-secure=false}).
 */
@Component
public class AuthCookieFactory {

    /** Ime refresh kolačića (access kolačić: {@link JwtCookieAuthenticationFilter#ACCESS_COOKIE}). */
    public static final String REFRESH_COOKIE = "sv_refresh";

    private final boolean secure;

    public AuthCookieFactory(AuthProperties properties) {
        this.secure = properties.isCookieSecure();
    }

    public ResponseCookie access(String token, long maxAgeSec) {
        return build(JwtCookieAuthenticationFilter.ACCESS_COOKIE, token, maxAgeSec);
    }

    public ResponseCookie refresh(String token, long maxAgeSec) {
        return build(REFRESH_COOKIE, token, maxAgeSec);
    }

    /** Kolačić koji odmah ističe (za odjavu / poništavanje). */
    public ResponseCookie clearAccess() {
        return build(JwtCookieAuthenticationFilter.ACCESS_COOKIE, "", 0);
    }

    public ResponseCookie clearRefresh() {
        return build(REFRESH_COOKIE, "", 0);
    }

    private ResponseCookie build(String name, String value, long maxAgeSec) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(secure)
                .sameSite("Strict")
                .path("/")
                .maxAge(maxAgeSec)
                .build();
    }
}
