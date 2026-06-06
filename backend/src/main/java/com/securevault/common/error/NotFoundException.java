package com.securevault.common.error;

import org.springframework.http.HttpStatus;

/**
 * Traženi resurs ne postoji ili nije dostupan. Mapira se na HTTP 404.
 *
 * <p>Koristi se i za isključene funkcije (npr. OIDC dok {@code app.oidc.enabled=false}) —
 * endpoint se tada ponaša kao da ne postoji, bez otkrivanja interne konfiguracije.
 */
public class NotFoundException extends AppException {

    public NotFoundException(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "NOT_FOUND";
    }

    @Override
    public HttpStatus status() {
        return HttpStatus.NOT_FOUND;
    }
}
