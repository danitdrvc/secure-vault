package com.securevault.common.error;

import org.springframework.http.HttpStatus;

/**
 * Autentikovan korisnik bez prava na traženu akciju, ili nalog koji nije {@code ACTIVE}
 * (deaktiviran/zamrznut) pri pokušaju logina. Mapira se na HTTP 403.
 */
public class ForbiddenException extends AppException {

    public ForbiddenException(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "FORBIDDEN";
    }

    @Override
    public HttpStatus status() {
        return HttpStatus.FORBIDDEN;
    }
}
