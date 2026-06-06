package com.securevault.auth.web;

/**
 * Telo odgovora na uspešan step2. Tokeni idu u HttpOnly kolačiće (NISU u telu); telo nosi
 * samo javne metapodatke naloga i šifrovani vault materijal za klijentsko otključavanje.
 */
public record LoginStep2Response(AuthUserResponse user, VaultMaterial vault) {
}
