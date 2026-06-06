package com.securevault.auth.service;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import org.springframework.stereotype.Service;

/**
 * TOTP drugi faktor preko {@code dev.samstevens.totp} (RFC 6238).
 *
 * <p>Server generiše base32 tajnu i {@code otpauth://} URI (za QR proviziju u authenticator
 * aplikaciju), te verifikuje 6-cifreni kod. Tajna se čuva šifrovana ({@link ServerSecretCipher}) —
 * to je auth materijal van zero-knowledge domena (server mora moći da verifikuje kod).
 */
@Service
public class TotpService {

    private static final String ISSUER = "SecureVault";
    private static final int DIGITS = 6;
    private static final int PERIOD_SECONDS = 30;

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeVerifier codeVerifier = new DefaultCodeVerifier(new DefaultCodeGenerator(), timeProvider);
    private final QrGenerator qrGenerator = new ZxingPngQrGenerator();

    /** Nova base32 TOTP tajna (proviziona vrednost; izlaže se klijentu samo kroz otpauth URI/QR). */
    public String generateSecret() {
        return secretGenerator.generate();
    }

    /** {@code otpauth://totp/...} URI koji authenticator aplikacija učitava (sadrži tajnu). */
    public String buildUri(String accountLabel, String secret) {
        return qrData(accountLabel, secret).getUri();
    }

    /** PNG QR kod kao {@code data:} URI (za prikaz u browseru). */
    public String buildQrDataUri(String accountLabel, String secret) {
        try {
            QrData data = qrData(accountLabel, secret);
            byte[] image = qrGenerator.generate(data);
            return Utils.getDataUriForImage(image, qrGenerator.getImageMimeType());
        } catch (QrGenerationException e) {
            throw new IllegalStateException("Generisanje QR koda nije uspelo", e);
        }
    }

    /** Verifikuje 6-cifreni kod uz toleranciju vremenskog prozora (default biblioteke). */
    public boolean verifyCode(String secret, String code) {
        return code != null && codeVerifier.isValidCode(secret, code);
    }

    private QrData qrData(String accountLabel, String secret) {
        return new QrData.Builder()
                .label(accountLabel)
                .secret(secret)
                .issuer(ISSUER)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(DIGITS)
                .period(PERIOD_SECONDS)
                .build();
    }
}
