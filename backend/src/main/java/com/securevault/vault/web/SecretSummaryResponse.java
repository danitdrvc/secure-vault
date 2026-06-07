package com.securevault.vault.web;

import com.securevault.vault.domain.Secret;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Metapodaci tajne za listu ({@code GET /vault/secrets}). NE sadrži {@code encryptedBlob} ni
 * {@code wrappedSecretKey} — samo neosetljive metapodatke. Tajni sadržaj se dohvata posebno
 * po {@code id}-u i dešifruje na klijentu.
 */
public record SecretSummaryResponse(UUID id, String name,
                                    OffsetDateTime createdAt, OffsetDateTime updatedAt) {

    public static SecretSummaryResponse from(Secret secret) {
        return new SecretSummaryResponse(secret.getId(), secret.getName(),
                secret.getCreatedAt(), secret.getUpdatedAt());
    }
}
