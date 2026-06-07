package com.securevault.vault.web;

import com.securevault.common.validation.Base64Bytes;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Telo zahteva za kreiranje tajne. Sav kripto materijal je već šifrovan na klijentu i stiže
 * kao base64 — server ga skladišti kao neprozirne bajtove (zero-knowledge):
 * <ul>
 *   <li>{@code name} — metapodatak (nije tajni sadržaj).</li>
 *   <li>{@code encryptedBlob} — AES-256-GCM(secretKey, plaintext): nonce(12) + ct + tag(16),
 *       tj. najmanje 28 B; gornja granica dozvoljava i veće tajne (npr. sertifikate).</li>
 *   <li>{@code wrappedSecretKey} — RSA-OAEP-2048(secretKey, vlasnikov javni ključ) = tačno 256 B.</li>
 *   <li>{@code rotationDays} — opcioni rok rotacije ({@code null} = bez rotacije); klijent ga
 *       koristi za upozorenje o isteku (Faza 8).</li>
 * </ul>
 */
public record CreateSecretRequest(

        @NotBlank
        @Size(max = 255)
        String name,

        @NotBlank
        @Base64Bytes(min = 28, max = 65_536, message = "encryptedBlob nije AES-GCM šifrat očekivane veličine")
        String encryptedBlob,

        @NotBlank
        @Base64Bytes(min = 256, max = 256, message = "wrappedSecretKey mora biti RSA-OAEP-2048 šifrat (256 bajtova)")
        String wrappedSecretKey,

        @Min(value = 1, message = "rotationDays mora biti pozitivan")
        @Max(value = 3650, message = "rotationDays je nerealno velik")
        Integer rotationDays
) {
}
