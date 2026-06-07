package com.securevault.vault.web;

import com.securevault.vault.domain.SecretAccess;

import java.util.UUID;

/**
 * Jedan korisnik koji ima pristup tajni ({@code GET /vault/secrets/{id}/access}, vlasnik-only).
 * Vlasnik ovim dobija listu primaoca da bi pri rotaciji uvio nov {@code secretKey} ka svakome.
 * Sadrži samo {@code userId} — nikad kripto materijal.
 */
public record SecretAccessResponse(UUID userId) {

    public static SecretAccessResponse from(SecretAccess access) {
        return new SecretAccessResponse(access.getUserId());
    }
}
