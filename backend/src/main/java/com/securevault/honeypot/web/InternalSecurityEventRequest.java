package com.securevault.honeypot.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Telo internog poziva kojim gateway prijavljuje sigurnosni događaj (npr. {@code IP_BLOCKED}).
 * {@code detail} je opcioni JSON string (jsonb kolona); ako je prazan, koristi se {@code "{}"}.
 */
public record InternalSecurityEventRequest(
        @NotBlank @Size(max = 32) String type,
        @Size(max = 64) String ip,
        String detail
) {
}
