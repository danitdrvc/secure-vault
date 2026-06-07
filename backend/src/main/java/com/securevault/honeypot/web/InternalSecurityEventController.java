package com.securevault.honeypot.web;

import com.securevault.common.error.UnauthorizedException;
import com.securevault.config.InternalProperties;
import com.securevault.honeypot.service.SecurityEventService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Interni (server-to-server) endpoint kojim gateway (Faza 9) prijavljuje sigurnosne događaje.
 *
 * <p>Rute pod {@code /internal/**} NISU izložene kroz gateway (njegova {@code /api/**} ruta ih
 * ne pokriva), pa spoljašnji klijent ne može do njih kroz jedinu ulaznu tačku. Dodatno, svaki
 * zahtev mora nositi tačan {@code X-Internal-Token} (deljeni token); u suprotnom {@code 401}.
 * Poređenje tokena je konstantno-vremensko (otpornost na timing napad).
 */
@RestController
@RequestMapping("/internal/security-events")
public class InternalSecurityEventController {

    public static final String INTERNAL_TOKEN_HEADER = "X-Internal-Token";

    private final SecurityEventService securityEventService;
    private final InternalProperties internalProperties;

    public InternalSecurityEventController(SecurityEventService securityEventService,
                                           InternalProperties internalProperties) {
        this.securityEventService = securityEventService;
        this.internalProperties = internalProperties;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public void record(@RequestHeader(value = INTERNAL_TOKEN_HEADER, required = false) String token,
                       @Valid @RequestBody InternalSecurityEventRequest request) {
        requireValidToken(token);
        securityEventService.record(request.type(), null, request.ip(), request.detail());
    }

    private void requireValidToken(String provided) {
        String expected = internalProperties.getToken();
        if (expected == null || expected.isBlank() || provided == null
                || !MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
                                          provided.getBytes(StandardCharsets.UTF_8))) {
            throw new UnauthorizedException("Nevažeći interni token.", "UNAUTHORIZED");
        }
    }
}
