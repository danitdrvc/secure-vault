package com.securevault.common.error;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.stream.Collectors;

/**
 * Globalno mapiranje grešaka u konzistentan {@link ErrorResponse}. NIKAD ne propušta
 * interne detalje (stack trace, SQL, imena kolona) klijentu (DEVELOPMENT_PLAN 5.2).
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AppException.class)
    public ResponseEntity<ErrorResponse> handleApp(AppException ex) {
        return ResponseEntity.status(ex.status()).body(ErrorResponse.of(ex.code(), ex.getMessage()));
    }

    /** Bean Validation (@Valid) — vraća koja su polja neispravna, bez internih detalja. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .collect(Collectors.joining("; "));
        if (message.isBlank()) {
            message = "Neispravan zahtev.";
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ErrorResponse.of("VALIDATION", message));
    }

    /** Neispravno/nepotpuno telo ili nepoznata polja (Jackson FAIL_ON_UNKNOWN_PROPERTIES). */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ErrorResponse.of("BAD_REQUEST", "Telo zahteva nije validno."));
    }

    /** Neispravan parametar putanje (npr. {@code id} koji nije validan UUID) — bez 500/internih detalja. */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErrorResponse> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ErrorResponse.of("BAD_REQUEST", "Neispravan parametar putanje."));
    }

    /**
     * Odbijanje na nivou metode ({@code @PreAuthorize}) — npr. {@code Developer} pokuša deljenje
     * koje sme samo {@code TEAM_LEAD}. Method security baca {@link AccessDeniedException} TOKOM
     * poziva kontrolera (unutar DispatcherServlet-a), pa je hvata ovaj advice (URL-bazirana
     * odbijanja i dalje obrađuje {@code RestAuthenticationEntryPoint} na nivou filtera). Isti
     * oblik {@code FORBIDDEN} odgovora u oba slučaja.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ErrorResponse.of("FORBIDDEN", "Nedovoljna prava za ovu akciju."));
    }

    /**
     * Nepoznata ruta (nema mapiranog handler-a ni statičkog resursa) → {@code 404}, umesto da
     * padne na catch-all {@code 500}. Ovo je ujedno garancija append-only audita: nad
     * {@code /admin/audit/log/**} ne postoji nijedna UPDATE/DELETE ruta — pokušaj vraća {@code 404}.
     */
    @ExceptionHandler({NoHandlerFoundException.class, NoResourceFoundException.class})
    public ResponseEntity<ErrorResponse> handleNotFound(Exception ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ErrorResponse.of("NOT_FOUND", "Resurs ne postoji."));
    }

    /** HTTP metoda koju ruta ne podržava (npr. {@code DELETE} na read-only audit ruti) → {@code 405}. */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(ErrorResponse.of("METHOD_NOT_ALLOWED", "Metoda nije podržana za ovaj resurs."));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse.of("INTERNAL", "Interna greška servera."));
    }
}
