package com.securevault.auth.web;

import com.securevault.auth.service.AuthService;
import com.securevault.auth.service.TokenService;
import com.securevault.common.error.UnauthorizedException;
import com.securevault.security.AuthenticatedUser;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Autentikacioni endpointi (Faza 4). Saobraćaj stiže kroz gateway
 * ({@code /api/auth/**} → {@code /auth/**}).
 *
 * <p>Tok: {@code login/params} (KDF parametri) → {@code login/step1} (lozinka → MFA tiket) →
 * {@code totp/setup} + {@code totp/verify} (prvi put) → {@code login/step2} (TOTP → sesija) →
 * {@code refresh} (rotacija). Tokeni žive u HttpOnly kolačićima — nikad u telu odgovora.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final TokenService tokenService;
    private final AuthCookieFactory cookieFactory;

    public AuthController(AuthService authService, TokenService tokenService, AuthCookieFactory cookieFactory) {
        this.authService = authService;
        this.tokenService = tokenService;
        this.cookieFactory = cookieFactory;
    }

    @PostMapping("/login/params")
    public LoginParamsResponse loginParams(@Valid @RequestBody LoginParamsRequest request) {
        return authService.loginParams(request);
    }

    @PostMapping("/login/step1")
    public LoginStep1Response step1(@Valid @RequestBody LoginStep1Request request) {
        return authService.step1(request);
    }

    @PostMapping("/totp/setup")
    public TotpSetupResponse totpSetup(@Valid @RequestBody TotpSetupRequest request) {
        return authService.totpSetup(request.mfaTicket());
    }

    @PostMapping("/totp/verify")
    public ResponseEntity<Void> totpVerify(@Valid @RequestBody TotpVerifyRequest request) {
        authService.totpVerify(request.mfaTicket(), request.totpCode());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/login/step2")
    public ResponseEntity<LoginStep2Response> step2(@Valid @RequestBody LoginStep2Request request) {
        AuthService.LoginResult result = authService.step2(request);
        return withSessionCookies(result.tokens()).body(result.body());
    }

    @PostMapping("/refresh")
    public ResponseEntity<Void> refresh(
            @CookieValue(name = AuthCookieFactory.REFRESH_COOKIE, required = false) String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new UnauthorizedException("Nedostaje refresh token.");
        }
        TokenService.IssuedTokens tokens = tokenService.rotate(refreshToken);
        return withSessionCookies(tokens).build();
    }

    @GetMapping("/me")
    public AuthUserResponse me(@AuthenticationPrincipal AuthenticatedUser principal) {
        return authService.me(principal.id());
    }

    /**
     * Šifrovani vault materijal za otključavanje (Faza 5). Zahteva važeću sesiju, ali sam
     * materijal je beskoristan bez master lozinke — koristi ga klijent posle OIDC prijave da
     * lokalno pozove {@code unlock}.
     */
    @GetMapping("/vault-material")
    public VaultMaterial vaultMaterial(@AuthenticationPrincipal AuthenticatedUser principal) {
        return authService.vaultMaterial(principal.id());
    }

    /** Postavlja oba sesijska kolačića (access + refresh) na odgovor. */
    private ResponseEntity.BodyBuilder withSessionCookies(TokenService.IssuedTokens tokens) {
        ResponseCookie access = cookieFactory.access(tokens.accessToken(), tokens.accessMaxAgeSec());
        ResponseCookie refresh = cookieFactory.refresh(tokens.refreshToken(), tokens.refreshMaxAgeSec());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, access.toString())
                .header(HttpHeaders.SET_COOKIE, refresh.toString());
    }
}
