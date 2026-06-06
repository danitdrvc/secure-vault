package com.securevault.auth.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/** Verifikacija TOTP koda tokom setup-a: na uspeh se uključuje {@code totp_enabled}. */
public record TotpVerifyRequest(
        @NotBlank String mfaTicket,
        @NotBlank
        @Pattern(regexp = "^[0-9]{6}$", message = "TOTP kod mora imati 6 cifara")
        String totpCode
) {
}
