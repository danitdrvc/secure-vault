package com.securevault.user.web;

import com.securevault.common.validation.Base64Bytes;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Telo zahteva za registraciju. Svi kripto artefakti stižu kao base64 stringovi i
 * server ih tretira kao neprozirne bajtove (zero-knowledge). Veličine su fiksne i
 * proistekle iz klijentskog kripto sloja (Faza 2):
 * <ul>
 *   <li>{@code kdfSalt} — 16 B (PBKDF2 so)</li>
 *   <li>{@code authKey} — 32 B (HKDF "vault-auth"); server čuva samo bcrypt(authKey)</li>
 *   <li>{@code encUsk} — 60 B = nonce(12) + AES-GCM(KEK, USK 32B) + tag(16)</li>
 *   <li>{@code publicKey} — ~294 B (RSA-2048 SPKI, plaintext po dizajnu)</li>
 *   <li>{@code encPrivateKey} — ~1245 B = nonce(12) + AES-GCM(USK, PKCS8 ~1217B) + tag(16)</li>
 * </ul>
 * Donja granica {@code encPrivateKey} je iznad veličine NEšifrovanog PKCS8 ključa — čime
 * se odbija slučajno poslat plaintext privatni ključ.
 */
public record RegisterRequest(

        @NotBlank
        @Size(min = 3, max = 64)
        @Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "dozvoljena su slova, cifre i znaci . _ -")
        String username,

        @NotBlank
        @Email
        @Size(max = 255)
        String email,

        @NotBlank
        @Base64Bytes(min = 16, max = 16, message = "kdfSalt mora biti tačno 16 bajtova (base64)")
        String kdfSalt,

        @Min(value = 600_000, message = "kdfIterations mora biti najmanje 600000")
        @Max(value = 10_000_000, message = "kdfIterations je nerealno velik")
        int kdfIterations,

        @NotBlank
        @Base64Bytes(min = 32, max = 32, message = "authKey mora biti tačno 32 bajta (base64)")
        String authKey,

        @NotBlank
        @Base64Bytes(min = 60, max = 60, message = "encUsk mora biti tačno 60 bajtova (base64)")
        String encUsk,

        @NotBlank
        @Base64Bytes(min = 290, max = 300, message = "publicKey nije RSA-2048 SPKI očekivane veličine")
        String publicKey,

        @NotBlank
        @Base64Bytes(min = 1230, max = 1300, message = "encPrivateKey nije šifrovan PKCS8 očekivane veličine")
        String encPrivateKey
) {
}
