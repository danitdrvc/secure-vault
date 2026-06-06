package com.securevault.common.error;

import org.springframework.http.HttpStatus;

/**
 * Neuspela autentikacija — pogrešni kredencijali, nevažeći/istekao MFA tiket ili refresh
 * token, ili istekao apsolutni cap sesije. Mapira se na HTTP 401.
 *
 * <p>Poruke su namerno opšte (ne otkrivaju da li postoji nalog niti koji faktor je pao),
 * a {@code code} može biti precizniji za klijentsku logiku (npr. {@code SESSION_EXPIRED}).
 */
public class UnauthorizedException extends AppException {

    private final String code;

    public UnauthorizedException(String message) {
        this(message, "UNAUTHORIZED");
    }

    public UnauthorizedException(String message, String code) {
        super(message);
        this.code = code;
    }

    @Override
    public String code() {
        return code;
    }

    @Override
    public HttpStatus status() {
        return HttpStatus.UNAUTHORIZED;
    }
}
