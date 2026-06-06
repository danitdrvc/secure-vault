package com.securevault.security;

import com.securevault.config.AuthProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Izdavanje i provera JWT tokena (HS256, jjwt 0.12.x).
 *
 * <p>Tri tipa tokena, razlikovana {@code typ} claim-om:
 * <ul>
 *   <li>{@code access}  — kratkoživeći; nosi {@code username} i {@code role}; ide u {@code sv_access} kolačić.</li>
 *   <li>{@code refresh} — rotirajući; nosi {@code sxp} (apsolutni cap sesije, epoch sek); ide u {@code sv_refresh} kolačić.</li>
 *   <li>{@code mfa}     — privremeni tiket koji povezuje korake logina (step1 → totp → step2).</li>
 * </ul>
 * Server NIKAD ne stavlja kripto materijal (USK, privatni ključ, master lozinku) u token.
 */
@Service
public class JwtService {

    public static final String TYPE_ACCESS = "access";
    public static final String TYPE_REFRESH = "refresh";
    public static final String TYPE_MFA = "mfa";
    /** Privremeni potpisani state/nonce token tokom OIDC redirect toka (Faza 5). */
    public static final String TYPE_OIDC_STATE = "oidc_state";

    private static final String CLAIM_TYPE = "typ";
    private static final String CLAIM_USERNAME = "username";
    private static final String CLAIM_ROLE = "role";
    /** Session expiry — apsolutni cap trajanja sesije (epoch sekunde). */
    private static final String CLAIM_SESSION_EXP = "sxp";
    private static final String CLAIM_STATE = "state";
    private static final String CLAIM_NONCE = "nonce";

    private final SecretKey key;
    private final String issuer;

    public JwtService(AuthProperties properties) {
        byte[] secret = properties.getJwtSecret().getBytes(StandardCharsets.UTF_8);
        // hmacShaKeyFor zahteva >= 32 bajta za HS256 — baca jasnu grešku na prekratku tajnu.
        this.key = Keys.hmacShaKeyFor(secret);
        this.issuer = properties.getJwtIssuer();
    }

    public String issueAccessToken(UUID userId, String username, String role, int ttlSeconds) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(issuer)
                .subject(userId.toString())
                .claim(CLAIM_TYPE, TYPE_ACCESS)
                .claim(CLAIM_USERNAME, username)
                .claim(CLAIM_ROLE, role)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ttlSeconds)))
                .signWith(key)
                .compact();
    }

    /**
     * Refresh token sa eksplicitnim trenutkom isteka i upisanim {@code sessionExp}
     * (apsolutni cap od logina) koji se NEPROMENJEN prenosi kroz sve rotacije.
     */
    public String issueRefreshToken(UUID userId, Instant expiresAt, long sessionExpEpochSec) {
        Instant now = Instant.now();
        return Jwts.builder()
                // jti garantuje da je svaki refresh token jedinstven (i kad su iat/exp/claims
                // isti, npr. kad sessionExp capuje refresh TTL i rotacija padne u istu sekundu) —
                // pa SHA-256 heš ne kolidira sa već upisanim u refresh_token tabeli.
                .id(UUID.randomUUID().toString())
                .issuer(issuer)
                .subject(userId.toString())
                .claim(CLAIM_TYPE, TYPE_REFRESH)
                .claim(CLAIM_SESSION_EXP, sessionExpEpochSec)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .signWith(key)
                .compact();
    }

    public String issueMfaTicket(UUID userId, int ttlSeconds) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(issuer)
                .subject(userId.toString())
                .claim(CLAIM_TYPE, TYPE_MFA)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ttlSeconds)))
                .signWith(key)
                .compact();
    }

    /**
     * Kratkoživeći potpisani token koji nosi OIDC {@code state} i {@code nonce}. Čuva se u
     * HttpOnly kolačiću tokom redirect toka; na callback-u se verifikuje da {@code state} iz
     * query parametra odgovara onome iz potpisanog kolačića (CSRF zaštita), a {@code nonce}
     * se prosleđuje proveri id_token-a.
     */
    public String issueOidcState(String state, String nonce, int ttlSeconds) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(issuer)
                .subject("oidc")
                .claim(CLAIM_TYPE, TYPE_OIDC_STATE)
                .claim(CLAIM_STATE, state)
                .claim(CLAIM_NONCE, nonce)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ttlSeconds)))
                .signWith(key)
                .compact();
    }

    public String stateValue(Claims claims) {
        return claims.get(CLAIM_STATE, String.class);
    }

    public String nonceValue(Claims claims) {
        return claims.get(CLAIM_NONCE, String.class);
    }

    /**
     * Verifikuje potpis i istek; vraća claim-ove. Baca {@link JwtException} (uklj.
     * {@link ExpiredJwtException}) za nevažeći/istekao token.
     */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .requireIssuer(issuer)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Verifikuje potpis ali NE baca na istek — vraća claim-ove i za istekao token.
     * Koristi se kod refresh-a da bi se apsolutni cap sesije ({@code sxp}) mogao
     * eksplicitno proveriti i vratiti jasnu poruku i kad je token istekao.
     */
    public Claims parseAllowingExpired(String token) {
        try {
            return parse(token);
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public String type(Claims claims) {
        return claims.get(CLAIM_TYPE, String.class);
    }

    public UUID subjectId(Claims claims) {
        return UUID.fromString(claims.getSubject());
    }

    public String username(Claims claims) {
        return claims.get(CLAIM_USERNAME, String.class);
    }

    public String role(Claims claims) {
        return claims.get(CLAIM_ROLE, String.class);
    }

    public long sessionExpEpochSec(Claims claims) {
        return claims.get(CLAIM_SESSION_EXP, Long.class);
    }
}
