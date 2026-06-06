package com.securevault.auth.service;

import com.securevault.auth.domain.RefreshToken;
import com.securevault.auth.repository.RefreshTokenRepository;
import com.securevault.common.error.ForbiddenException;
import com.securevault.common.error.UnauthorizedException;
import com.securevault.policy.domain.SecurityPolicy;
import com.securevault.policy.repository.SecurityPolicyRepository;
import com.securevault.security.JwtService;
import com.securevault.user.domain.User;
import com.securevault.user.domain.UserStatus;
import com.securevault.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Izdavanje i rotacija access/refresh tokena, uz apsolutni cap trajanja sesije iz politike.
 *
 * <p>Refresh token je JWT (nosi {@code sessionExp}); u {@code refresh_token} tabeli se čuva
 * samo njegov {@code SHA-256} heš radi revokacije/rotacije i audita. Pri svakom refresh-u:
 * stari red se {@code revoked}, izdaje se nov par. Istek novog refresh-a je
 * {@code min(now + refresh_token_ttl_sec, session_expires_at)} — posle apsolutnog capa
 * ({@code session_max_ttl_sec} od logina) refresh se odbija ({@code 401}) i traži se ponovni login.
 */
@Service
public class TokenService {

    /** Šifrovani artefakti + trajanja za kolačiće. */
    public record IssuedTokens(String accessToken, long accessMaxAgeSec,
                               String refreshToken, long refreshMaxAgeSec) {
    }

    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final SecurityPolicyRepository policyRepository;
    private final UserRepository userRepository;

    public TokenService(JwtService jwtService,
                        RefreshTokenRepository refreshTokenRepository,
                        SecurityPolicyRepository policyRepository,
                        UserRepository userRepository) {
        this.jwtService = jwtService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.policyRepository = policyRepository;
        this.userRepository = userRepository;
    }

    /** Inicijalni par pri uspešnom loginu (step2). Postavlja apsolutni cap sesije. */
    @Transactional
    public IssuedTokens issueForLogin(User user) {
        SecurityPolicy policy = activePolicy();
        Instant now = Instant.now();
        Instant sessionExp = now.plusSeconds(policy.getSessionMaxTtlSec());
        Instant refreshExp = earliest(now.plusSeconds(policy.getRefreshTokenTtlSec()), sessionExp);

        String access = jwtService.issueAccessToken(
                user.getId(), user.getUsername(), user.getRole().name(), policy.getAccessTokenTtlSec());
        String refresh = jwtService.issueRefreshToken(user.getId(), refreshExp, sessionExp.getEpochSecond());
        persistRefresh(user.getId(), refresh, refreshExp, null);

        return new IssuedTokens(access, policy.getAccessTokenTtlSec(),
                refresh, secondsUntil(now, refreshExp));
    }

    /**
     * Rotira refresh token: validira ga, revoke-uje stari i izdaje nov par. Apsolutni cap
     * sesije ({@code sessionExp}) se proverava PRE svega — i kad je token istekao zbog capa,
     * vraća se jasan {@code SESSION_EXPIRED}.
     */
    @Transactional
    public IssuedTokens rotate(String refreshToken) {
        Claims claims = parseRefresh(refreshToken);
        if (!JwtService.TYPE_REFRESH.equals(jwtService.type(claims))) {
            throw new UnauthorizedException("Nevažeći refresh token.");
        }

        Instant now = Instant.now();
        long sessionExpSec = jwtService.sessionExpEpochSec(claims);
        if (sessionExpSec <= now.getEpochSecond()) {
            // Apsolutni cap sesije je prošao — ponovni login je jedini izlaz.
            throw new UnauthorizedException("Sesija je istekla, prijavite se ponovo.", "SESSION_EXPIRED");
        }
        if (claims.getExpiration().toInstant().isBefore(now)) {
            throw new UnauthorizedException("Refresh token je istekao.");
        }

        RefreshToken stored = refreshTokenRepository.findByTokenHash(sha256Hex(refreshToken))
                .orElseThrow(() -> new UnauthorizedException("Nepoznat refresh token."));
        if (stored.isRevoked()) {
            throw new UnauthorizedException("Refresh token je već iskorišćen.");
        }
        if (stored.getExpiresAt().toInstant().isBefore(now)) {
            throw new UnauthorizedException("Refresh token je istekao.");
        }

        UUID userId = jwtService.subjectId(claims);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UnauthorizedException("Nalog ne postoji."));
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ForbiddenException("Nalog nije aktivan.");
        }

        // Rotacija: stari refresh više nikad ne važi.
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        SecurityPolicy policy = activePolicy();
        Instant sessionExp = Instant.ofEpochSecond(sessionExpSec);
        Instant refreshExp = earliest(now.plusSeconds(policy.getRefreshTokenTtlSec()), sessionExp);

        String newRefresh = jwtService.issueRefreshToken(userId, refreshExp, sessionExpSec);
        persistRefresh(userId, newRefresh, refreshExp, stored.getId());
        String access = jwtService.issueAccessToken(
                userId, user.getUsername(), user.getRole().name(), policy.getAccessTokenTtlSec());

        return new IssuedTokens(access, policy.getAccessTokenTtlSec(),
                newRefresh, secondsUntil(now, refreshExp));
    }

    private Claims parseRefresh(String refreshToken) {
        try {
            return jwtService.parseAllowingExpired(refreshToken);
        } catch (JwtException | IllegalArgumentException e) {
            throw new UnauthorizedException("Nevažeći refresh token.");
        }
    }

    private void persistRefresh(UUID userId, String token, Instant expiresAt, UUID rotatedFrom) {
        RefreshToken rt = new RefreshToken();
        rt.setUserId(userId);
        rt.setTokenHash(sha256Hex(token));
        rt.setExpiresAt(OffsetDateTime.ofInstant(expiresAt, ZoneOffset.UTC));
        rt.setRevoked(false);
        rt.setRotatedFrom(rotatedFrom);
        refreshTokenRepository.save(rt);
    }

    private SecurityPolicy activePolicy() {
        return policyRepository.findFirstByActiveTrue()
                .orElseThrow(() -> new IllegalStateException("Nema aktivne security_policy."));
    }

    private static Instant earliest(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }

    private static long secondsUntil(Instant from, Instant to) {
        return Math.max(0, Duration.between(from, to).getSeconds());
    }

    static String sha256Hex(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 nije dostupan u JVM-u", e);
        }
    }
}
