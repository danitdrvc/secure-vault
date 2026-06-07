package com.securevault.common.error;

import org.springframework.http.HttpStatus;

/**
 * Semantički neispravan zahtev koji prođe Bean Validation ali prekrši poslovno pravilo
 * (npr. rotacija tajne koja ne re-wrap-uje SVE postojeće primaoce). Mapira se na HTTP 400.
 *
 * <p>Razlika u odnosu na {@code @Valid} greške (koje hvata {@code GlobalExceptionHandler}):
 * ovu grešku baca servisni sloj kad je telo formalno ispravno, ali narušava invarijantu.
 */
public class ValidationException extends AppException {

    public ValidationException(String message) {
        super(message);
    }

    @Override
    public String code() {
        return "VALIDATION";
    }

    @Override
    public HttpStatus status() {
        return HttpStatus.BAD_REQUEST;
    }
}
