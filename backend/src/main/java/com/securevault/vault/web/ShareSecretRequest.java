package com.securevault.vault.web;

import com.securevault.common.validation.Base64Bytes;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

/**
 * Telo zahteva za deljenje tajne ({@code POST /vault/secrets/{id}/share}, Faza 7).
 *
 * <p>Onaj ko deli na klijentu otvori svoj {@code wrappedSecretKey} privatnim ključem, pa isti
 * {@code secretKey} uvije ka javnom ključu PRIMAOCA (RSA-OAEP). Server prima samo taj novi
 * šifrat — nikad plaintext {@code secretKey} (zero-knowledge). {@code encryptedBlob} se NE menja.
 * <ul>
 *   <li>{@code recipientId} — kome se deli (njegov javni ključ je iskorišćen za uvijanje).</li>
 *   <li>{@code wrappedSecretKey} — RSA-OAEP-2048(secretKey, primaočev javni ključ) = tačno 256 B.</li>
 * </ul>
 */
public record ShareSecretRequest(

        @NotNull
        UUID recipientId,

        @NotBlank
        @Base64Bytes(min = 256, max = 256, message = "wrappedSecretKey mora biti RSA-OAEP-2048 šifrat (256 bajtova)")
        String wrappedSecretKey
) {
}
