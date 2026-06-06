package com.securevault.auth.web;

import com.securevault.auth.oidc.OidcService;
import com.securevault.auth.service.TokenService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CookieValue;

/**
 * OIDC prijava (Faza 5). Saobraćaj stiže kroz gateway ({@code /api/auth/oidc/**}).
 *
 * <p>{@code GET /oidc/start} preusmerava browser na provajdera (uz potpisani state/nonce
 * kolačić). {@code GET /oidc/callback} obrađuje povratak: na uspeh postavlja iste sesijske
 * kolačiće kao Faza 4 i preusmerava na frontend — ali NE vraća vault materijal, pa vault
 * ostaje zaključan dok korisnik lokalno ne unese master lozinku (zero-knowledge očuvan).
 */
@RestController
@RequestMapping("/auth")
public class OidcController {

    private final OidcService oidcService;
    private final AuthCookieFactory cookieFactory;

    public OidcController(OidcService oidcService, AuthCookieFactory cookieFactory) {
        this.oidcService = oidcService;
        this.cookieFactory = cookieFactory;
    }

    @GetMapping("/oidc/start")
    public ResponseEntity<Void> start() {
        OidcService.StartRedirect redirect = oidcService.start();
        ResponseCookie stateCookie = cookieFactory.oidcState(redirect.stateToken(), redirect.stateTtlSec());
        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.SET_COOKIE, stateCookie.toString())
                .header(HttpHeaders.LOCATION, redirect.authorizationUrl())
                .build();
    }

    @GetMapping("/oidc/callback")
    public ResponseEntity<Void> callback(
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "error", required = false) String error,
            @CookieValue(name = AuthCookieFactory.OIDC_STATE_COOKIE, required = false) String stateCookie) {

        OidcService.CallbackResult result = oidcService.callback(code, state, error, stateCookie);

        ResponseEntity.BodyBuilder builder = ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, result.redirectUrl())
                // state kolačić je jednokratan — uvek ga poništi posle callback-a.
                .header(HttpHeaders.SET_COOKIE, cookieFactory.clearOidcState().toString());

        TokenService.IssuedTokens tokens = result.tokens();
        if (tokens != null) {
            builder.header(HttpHeaders.SET_COOKIE,
                            cookieFactory.access(tokens.accessToken(), tokens.accessMaxAgeSec()).toString())
                    .header(HttpHeaders.SET_COOKIE,
                            cookieFactory.refresh(tokens.refreshToken(), tokens.refreshMaxAgeSec()).toString());
        }
        return builder.build();
    }
}
