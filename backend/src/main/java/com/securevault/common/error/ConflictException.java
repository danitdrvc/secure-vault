package com.securevault.common.error;

import org.springframework.http.HttpStatus;

/**
 * Konflikt sa postojećim stanjem — npr. zauzeto korisničko ime ili email pri registraciji.
 * Mapira se na HTTP 409.
 */
public class ConflictException extends AppException {

    public ConflictException(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "CONFLICT";
    }

    @Override
    public HttpStatus status() {
        return HttpStatus.CONFLICT;
    }
}
