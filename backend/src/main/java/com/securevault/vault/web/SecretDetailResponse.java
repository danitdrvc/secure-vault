package com.securevault.vault.web;

import com.securevault.vault.domain.Secret;

import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.UUID;

/**
 * Pun sadržaj tajne za jednog korisnika ({@code GET /vault/secrets/{id}}). Oba kripto polja su
 * base64 šifrat koji server ne može dešifrovati (zero-knowledge):
 * <ul>
 *   <li>{@code encryptedBlob} — AES-256-GCM(secretKey, plaintext).</li>
 *   <li>{@code wrappedSecretKey} — secretKey uvijen ka javnom ključu OVOG korisnika (njegov red
 *       u {@code secret_access}); samo njegov privatni ključ ga otvara.</li>
 * </ul>
 */
public record SecretDetailResponse(UUID id, String name, String encryptedBlob,
                                   String wrappedSecretKey,
                                   OffsetDateTime createdAt, OffsetDateTime updatedAt) {

    public static SecretDetailResponse from(Secret secret, byte[] wrappedSecretKey) {
        Base64.Encoder b64 = Base64.getEncoder();
        return new SecretDetailResponse(
                secret.getId(),
                secret.getName(),
                b64.encodeToString(secret.getEncryptedBlob()),
                b64.encodeToString(wrappedSecretKey),
                secret.getCreatedAt(),
                secret.getUpdatedAt());
    }
}
