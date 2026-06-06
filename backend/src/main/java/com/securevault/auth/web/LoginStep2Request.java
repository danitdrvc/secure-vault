package com.securevault.auth.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Drugi korak logina: {@code mfaTicket} iz step1 + tekući TOTP kod. Na uspeh server izdaje
 * access/refresh kolačiće i vraća šifrovani vault materijal za otključavanje na klijentu.
 */
public record LoginStep2Request(
        @NotBlank String mfaTicket,
        @NotBlank
        @Pattern(regexp = "^[0-9]{6}$", message = "TOTP kod mora imati 6 cifara")
        String totpCode
) {
}
