package com.securevault.auth.web;

/**
 * Odgovor na step1: privremeni {@code mfaTicket} za sledeći korak. {@code totpEnabled}
 * govori klijentu da li da pređe na unos koda (true) ili prvo na TOTP setup (false).
 */
public record LoginStep1Response(String mfaTicket, boolean mfaRequired, boolean totpEnabled) {
}
