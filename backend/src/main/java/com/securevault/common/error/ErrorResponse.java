package com.securevault.common.error;

/**
 * Konzistentan oblik greške koji se vraća klijentu (DEVELOPMENT_PLAN 5.2):
 * {@code { "error": { "code": "...", "message": "..." } }}.
 * Nikad ne sadrži interne detalje (stack trace, SQL, imena kolona).
 */
public record ErrorResponse(Body error) {

    public record Body(String code, String message) {
    }

    public static ErrorResponse of(String code, String message) {
        return new ErrorResponse(new Body(code, message));
    }
}
