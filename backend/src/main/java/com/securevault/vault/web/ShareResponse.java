package com.securevault.vault.web;

import com.securevault.vault.domain.SecretAccess;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Potvrda deljenja ({@code POST /vault/secrets/{id}/share}, Faza 7). Sadrži samo metapodatke
 * novonastalog pristupnog reda — nikad kripto materijal.
 */
public record ShareResponse(UUID secretId, UUID recipientId, UUID grantedById,
                            OffsetDateTime createdAt) {

    public static ShareResponse from(SecretAccess access) {
        return new ShareResponse(
                access.getSecretId(),
                access.getUserId(),
                access.getGrantedById(),
                access.getCreatedAt());
    }
}
