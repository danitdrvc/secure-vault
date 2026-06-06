package com.securevault.auth.oidc;

import com.securevault.audit.service.AuditService;
import com.securevault.auth.service.TokenService;
import com.securevault.common.error.NotFoundException;
import com.securevault.config.OidcProperties;
import com.securevault.security.JwtService;
import com.securevault.user.domain.User;
import com.securevault.user.domain.UserStatus;
import com.securevault.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

/**
 * Orkestracija OIDC prijave (Faza 5): start (redirect na provajdera) i callback (razmena +
 * mapiranje na nalog + izdavanje sesije).
 *
 * <p><b>Zero-knowledge:</b> uspešan OIDC callback izdaje SAMO sesijske tokene (kao Faza 4) i
 * NE vraća nikakav vault materijal. Vault ostaje zaključan dok korisnik ne unese master lozinku
 * i klijent lokalno ne pozove {@code unlock} (klijent posebno dohvati šifrovani materijal sa
 * {@code GET /auth/vault-material}). Server tako i dalje nikad ne vidi ključeve.
 *
 * <p>Greške u callback-u (nepoklapanje state-a, neuspela verifikacija, nepovezan/neaktivan
 * nalog) ne vraćaju stack trace ni session kolačiće — browser se preusmerava na konfigurisani
 * frontend error URL.
 */
@Service
public class OidcService {

    private static final Logger log = LoggerFactory.getLogger(OidcService.class);
    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder URL_B64 = Base64.getUrlEncoder().withoutPadding();

    /** Redirect na provajdera + state/nonce kolačić koji controller postavlja. */
    public record StartRedirect(String authorizationUrl, String stateToken, int stateTtlSec) {
    }

    /**
     * Ishod callback-a: {@code tokens} je {@code null} kada prijava ne uspe (controller tada
     * ne postavlja sesijske kolačiće). {@code redirectUrl} je frontend success/error URL.
     */
    public record CallbackResult(TokenService.IssuedTokens tokens, String redirectUrl) {
        boolean succeeded() {
            return tokens != null;
        }
    }

    private final OidcProperties properties;
    private final OidcAuthenticator authenticator;
    private final JwtService jwtService;
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final AuditService auditService;

    public OidcService(OidcProperties properties,
                       OidcAuthenticator authenticator,
                       JwtService jwtService,
                       TokenService tokenService,
                       UserRepository userRepository,
                       AuditService auditService) {
        this.properties = properties;
        this.authenticator = authenticator;
        this.jwtService = jwtService;
        this.tokenService = tokenService;
        this.userRepository = userRepository;
        this.auditService = auditService;
    }

    /** Gradi authorization redirect URL i potpisani state/nonce token. */
    public StartRedirect start() {
        requireEnabled();
        String state = randomToken();
        String nonce = randomToken();

        String authorizationUrl = UriComponentsBuilder.fromUriString(properties.getAuthorizationUri())
                .queryParam("response_type", "code")
                .queryParam("client_id", properties.getClientId())
                .queryParam("redirect_uri", properties.getRedirectUri())
                .queryParam("scope", properties.getScopes())
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .build()
                .encode()
                .toUriString();

        String stateToken = jwtService.issueOidcState(state, nonce, properties.getStateTtlSec());
        return new StartRedirect(authorizationUrl, stateToken, properties.getStateTtlSec());
    }

    /**
     * Obrađuje provajderov callback. Validira state (CSRF), verifikuje id_token, mapira
     * {@code sub} na postojeći nalog i izdaje sesiju. Svaki neuspeh → redirect na error URL.
     */
    @Transactional
    public CallbackResult callback(String code, String state, String error, String stateCookieToken) {
        requireEnabled();

        if (error != null && !error.isBlank()) {
            log.warn("OIDC callback: provajder vratio grešku '{}'.", error);
            return failure();
        }
        if (code == null || code.isBlank()) {
            return failure();
        }

        String expectedNonce = verifyState(state, stateCookieToken);
        if (expectedNonce == null) {
            return failure();
        }

        OidcIdentity identity;
        try {
            identity = authenticator.authenticate(code, expectedNonce);
        } catch (RuntimeException e) {
            log.warn("OIDC verifikacija nije uspela: {}", e.getMessage());
            return failure();
        }

        Optional<User> match = resolveUser(identity);
        if (match.isEmpty()) {
            log.warn("OIDC prijava odbijena: identitet nije povezan ni sa jednim nalogom.");
            return failure();
        }
        User user = match.get();
        if (user.getStatus() != UserStatus.ACTIVE) {
            log.warn("OIDC prijava odbijena: nalog nije aktivan.");
            return failure();
        }

        TokenService.IssuedTokens tokens = tokenService.issueForLogin(user);
        auditService.record("OIDC_LOGIN_SUCCESS", user.getId(), "users/" + user.getId(), "{}");
        return new CallbackResult(tokens, properties.getPostLoginRedirectUri());
    }

    /**
     * Mapira OIDC identitet na nalog. Prvo po {@code oidc_subject} (već povezan nalog). Ako nema,
     * pri PRVOJ prijavi povezuje po VERIFIKOVANOM email-u: nalog sa istim email-om koji još nema
     * povezan {@code oidc_subject} se trajno poveže sa ovim {@code sub}. Bezbedno jer:
     * (a) provajder je potvrdio vlasništvo nad email-om ({@code email_verified}); (b) OIDC sesija
     * i dalje NE otključava vault (master lozinka je obavezna), pa povezivanje ne daje pristup
     * tajnama. Nalog koji već ima DRUGI {@code oidc_subject} se ne preuzima.
     */
    private Optional<User> resolveUser(OidcIdentity identity) {
        Optional<User> bySubject = userRepository.findByOidcSubject(identity.subject());
        if (bySubject.isPresent()) {
            return bySubject;
        }
        if (!identity.emailVerified() || identity.email() == null || identity.email().isBlank()) {
            return Optional.empty();
        }
        Optional<User> byEmail = userRepository.findByEmail(identity.email());
        if (byEmail.isEmpty() || byEmail.get().getOidcSubject() != null) {
            return Optional.empty(); // nepoznat email ili već povezan sa drugim OIDC identitetom
        }
        User user = byEmail.get();
        user.setOidcSubject(identity.subject()); // perzistira se kroz @Transactional
        log.info("OIDC: nalog povezan sa eksternim identitetom po verifikovanom email-u.");
        return Optional.of(user);
    }

    /** Verifikuje potpisani state kolačić i da query {@code state} odgovara; vraća nonce ili null. */
    private String verifyState(String state, String stateCookieToken) {
        if (state == null || state.isBlank() || stateCookieToken == null || stateCookieToken.isBlank()) {
            return null;
        }
        Claims claims;
        try {
            claims = jwtService.parse(stateCookieToken);
        } catch (JwtException | IllegalArgumentException e) {
            return null;
        }
        if (!JwtService.TYPE_OIDC_STATE.equals(jwtService.type(claims))) {
            return null;
        }
        if (!state.equals(jwtService.stateValue(claims))) {
            return null; // state iz query-ja ne odgovara potpisanom (mogući CSRF)
        }
        return jwtService.nonceValue(claims);
    }

    private CallbackResult failure() {
        return new CallbackResult(null, properties.getPostLoginErrorUri());
    }

    private void requireEnabled() {
        if (!properties.isEnabled()) {
            throw new NotFoundException("OIDC prijava nije omogućena.");
        }
    }

    private static String randomToken() {
        byte[] bytes = new byte[32];
        RNG.nextBytes(bytes);
        return URL_B64.encodeToString(bytes);
    }
}
