package com.securevault.auth.web;

import jakarta.validation.constraints.NotBlank;

/** TOTP setup je autorizovan privremenim {@code mfaTicket}-om iz step1 (dokaz lozinke). */
public record TotpSetupRequest(@NotBlank String mfaTicket) {
}
