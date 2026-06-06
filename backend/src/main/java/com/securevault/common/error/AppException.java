package com.securevault.common.error;

import org.springframework.http.HttpStatus;

/**
 * Bazna tipizovana aplikaciona greška. Nosi stabilan {@code code} i HTTP {@code status}
 * koje {@link GlobalExceptionHandler} mapira u konzistentan odgovor
 * {@code { "error": { "code": ..., "message": ... } }} (vidi DEVELOPMENT_PLAN 5.2).
 */
public abstract class AppException extends RuntimeException {

    protected AppException(String message) {
        super(message);
    }

    /** Stabilan, mašinski-čitljiv kod greške (npr. {@code CONFLICT}). */
    public abstract String code();

    /** HTTP status koji se vraća klijentu. */
    public abstract HttpStatus status();
}
