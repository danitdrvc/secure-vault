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

    /** Privremeni OIDC state/nonce kolačić (Faza 5). */
    public static final String OIDC_STATE_COOKIE = "sv_oidc_state";

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

    /**
     * OIDC state kolačić. {@code SameSite=Lax} (NE Strict) jer provajder vraća browser na
     * callback cross-site GET-om — uz Strict kolačić ne bi bio poslat i state provera bi pala.
     * Lax je dovoljan: šalje se na top-level navigacijama, a sadržaj je kratkoživeći potpisani
     * token (ne sesija).
     */
    public ResponseCookie oidcState(String token, long maxAgeSec) {
        return buildLax(OIDC_STATE_COOKIE, token, maxAgeSec);
    }

    public ResponseCookie clearOidcState() {
        return buildLax(OIDC_STATE_COOKIE, "", 0);
    }

    private ResponseCookie build(String name, String value, long maxAgeSec) {
        return cookie(name, value, maxAgeSec, "Strict");
    }

    private ResponseCookie buildLax(String name, String value, long maxAgeSec) {
        return cookie(name, value, maxAgeSec, "Lax");
    }

    private ResponseCookie cookie(String name, String value, long maxAgeSec, String sameSite) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(secure)
                .sameSite(sameSite)
                .path("/")
                .maxAge(maxAgeSec)
                .build();
    }
}
