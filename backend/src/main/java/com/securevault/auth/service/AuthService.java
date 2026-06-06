package com.securevault.auth.service;

import com.securevault.audit.service.AuditService;
import com.securevault.auth.web.AuthUserResponse;
import com.securevault.auth.web.LoginParamsRequest;
import com.securevault.auth.web.LoginParamsResponse;
import com.securevault.auth.web.LoginStep1Request;
import com.securevault.auth.web.LoginStep1Response;
import com.securevault.auth.web.LoginStep2Request;
import com.securevault.auth.web.LoginStep2Response;
import com.securevault.auth.web.TotpSetupResponse;
import com.securevault.auth.web.VaultMaterial;
import com.securevault.common.error.ForbiddenException;
import com.securevault.common.error.UnauthorizedException;
import com.securevault.config.AuthProperties;
import com.securevault.security.JwtService;
import com.securevault.user.domain.User;
import com.securevault.user.domain.UserStatus;
import com.securevault.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/**
 * Orkestracija login toka: lozinka (bcrypt) → TOTP (drugi faktor) → izdavanje sesije.
 *
 * <p>Zero-knowledge ostaje očuvan: server vidi samo {@code authKey} (i čuva bcrypt heš) i
 * šifrovane vault artefakte koje vraća klijentu na otključavanje. Master lozinka, KEK, USK i
 * privatni ključ NIKAD ne dolaze do servera.
 */
@Service
public class AuthService {

    /** Kombinovani rezultat step2: tokeni (za kolačiće) + telo odgovora. */
    public record LoginResult(TokenService.IssuedTokens tokens, LoginStep2Response body) {
    }

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TotpService totpService;
    private final ServerSecretCipher serverSecretCipher;
    private final TokenService tokenService;
    private final AuthProperties authProperties;
    private final AuditService auditService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       TotpService totpService,
                       ServerSecretCipher serverSecretCipher,
                       TokenService tokenService,
                       AuthProperties authProperties,
                       AuditService auditService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.totpService = totpService;
        this.serverSecretCipher = serverSecretCipher;
        this.tokenService = tokenService;
        this.authProperties = authProperties;
        this.auditService = auditService;
    }

    /**
     * Pre-login KDF parametri. Za nepostojeći nalog vraća DETERMINISTIČKI pseudo-salt
     * (da se kroz salt ne može utvrditi postoji li korisnik — otpornost na enumeraciju).
     */
    @Transactional(readOnly = true)
    public LoginParamsResponse loginParams(LoginParamsRequest request) {
        Base64.Encoder b64 = Base64.getEncoder();
        return userRepository.findByUsername(request.username())
                .map(u -> new LoginParamsResponse(b64.encodeToString(u.getKdfSalt()), u.getKdfIterations()))
                .orElseGet(() -> new LoginParamsResponse(
                        b64.encodeToString(pseudoSalt(request.username())), 600_000));
    }

    /** Korak 1: provera lozinke (bcrypt). Na uspeh izdaje privremeni MFA tiket. */
    @Transactional(readOnly = true)
    public LoginStep1Response step1(LoginStep1Request request) {
        User user = userRepository.findByUsername(request.username())
                .filter(u -> passwordEncoder.matches(request.authKey(), u.getAuthHash()))
                .orElseThrow(() -> new UnauthorizedException("Pogrešno korisničko ime ili lozinka."));

        // Deaktiviran/zamrznut nalog ne sme dalje (Faza 8 detaljnije; ovde osnovna provera).
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ForbiddenException("Nalog nije aktivan.");
        }

        String ticket = jwtService.issueMfaTicket(user.getId(), authProperties.getMfaTicketTtlSec());
        return new LoginStep1Response(ticket, true, user.isTotpEnabled());
    }

    /** TOTP setup: generiše i čuva (šifrovanu) tajnu; vraća otpauth URI + QR. Tajna je „pending" dok se ne verifikuje. */
    @Transactional
    public TotpSetupResponse totpSetup(String mfaTicket) {
        User user = requireMfaUser(mfaTicket);

        String secret = totpService.generateSecret();
        user.setTotpSecretEnc(serverSecretCipher.encrypt(secret));
        user.setTotpEnabled(false); // mora se verifikovati pre nego što postane drugi faktor
        userRepository.save(user);

        String label = user.getUsername();
        return new TotpSetupResponse(totpService.buildUri(label, secret), totpService.buildQrDataUri(label, secret));
    }

    /** Verifikuje TOTP kod tokom setup-a i uključuje {@code totp_enabled}. */
    @Transactional
    public void totpVerify(String mfaTicket, String code) {
        User user = requireMfaUser(mfaTicket);
        String secret = decryptTotpSecret(user);
        if (!totpService.verifyCode(secret, code)) {
            throw new UnauthorizedException("Neispravan TOTP kod.");
        }
        user.setTotpEnabled(true);
        userRepository.save(user);
        auditService.record("TOTP_ENABLED", user.getId(), "users/" + user.getId(), "{}");
    }

    /** Korak 2: verifikuje TOTP i izdaje sesiju; vraća vault materijal za klijentsko otključavanje. */
    @Transactional
    public LoginResult step2(LoginStep2Request request) {
        User user = requireMfaUser(request.mfaTicket());
        if (!user.isTotpEnabled()) {
            throw new UnauthorizedException("TOTP nije podešen. Prvo dovršite podešavanje.", "TOTP_SETUP_REQUIRED");
        }
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ForbiddenException("Nalog nije aktivan.");
        }
        String secret = decryptTotpSecret(user);
        if (!totpService.verifyCode(secret, request.totpCode())) {
            throw new UnauthorizedException("Neispravan TOTP kod.");
        }

        TokenService.IssuedTokens tokens = tokenService.issueForLogin(user);
        auditService.record("LOGIN_SUCCESS", user.getId(), "users/" + user.getId(), "{}");

        LoginStep2Response body = new LoginStep2Response(AuthUserResponse.from(user), VaultMaterial.from(user));
        return new LoginResult(tokens, body);
    }

    /** Trenutni autentikovan korisnik (za {@code GET /auth/me}). */
    @Transactional(readOnly = true)
    public AuthUserResponse me(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UnauthorizedException("Nalog ne postoji."));
        return AuthUserResponse.from(user);
    }

    /**
     * Šifrovani vault materijal za autentikovanog korisnika (za {@code GET /auth/vault-material}).
     *
     * <p>Koristi se posle OIDC prijave (Faza 5) gde sesija postoji ali vault još nije otključan:
     * klijent dohvati ovaj (samo šifrat) materijal i lokalno pozove {@code unlock} sa master
     * lozinkom. Server i dalje ne može ništa dešifrovati — zero-knowledge je očuvan.
     */
    @Transactional(readOnly = true)
    public VaultMaterial vaultMaterial(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UnauthorizedException("Nalog ne postoji."));
        return VaultMaterial.from(user);
    }

    private User requireMfaUser(String mfaTicket) {
        Claims claims;
        try {
            claims = jwtService.parse(mfaTicket);
        } catch (JwtException | IllegalArgumentException e) {
            throw new UnauthorizedException("MFA tiket je nevažeći ili istekao.");
        }
        if (!JwtService.TYPE_MFA.equals(jwtService.type(claims))) {
            throw new UnauthorizedException("MFA tiket je nevažeći.");
        }
        return userRepository.findById(jwtService.subjectId(claims))
                .orElseThrow(() -> new UnauthorizedException("Nalog ne postoji."));
    }

    private String decryptTotpSecret(User user) {
        byte[] enc = user.getTotpSecretEnc();
        if (enc == null || enc.length == 0) {
            throw new UnauthorizedException("TOTP nije podešen.", "TOTP_SETUP_REQUIRED");
        }
        return serverSecretCipher.decrypt(enc);
    }

    /** Stabilan 16-bajtni pseudo-salt iz {@code SHA-256(kms || username)} (nije tajna; samo anti-enumeracija). */
    private byte[] pseudoSalt(String username) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((authProperties.getServerKmsKey() + ":" + username).getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOf(digest, 16);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 nije dostupan u JVM-u", e);
        }
    }
}
