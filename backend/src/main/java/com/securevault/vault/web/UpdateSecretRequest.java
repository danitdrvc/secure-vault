package com.securevault.vault.web;

import com.securevault.common.validation.Base64Bytes;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Telo zahteva za izmenu tajne. Klijent dešifruje postojeću tajnu, izmeni plaintext i ponovo
 * ga šifruje ISTIM {@code secretKey}-em (koji je dobio otključavanjem postojećeg
 * {@code wrappedSecretKey}), pa šalje samo novi {@code name} i {@code encryptedBlob}. Pošto se
 * {@code secretKey} ne menja, {@code wrapped_secret_key} ostaje važeći (bitno za buduće deljenje
 * iz Faze 7). Rotacija samog {@code secretKey}-a (re-wrap ka svim primaocima) je tema Faze 8.
 */
public record UpdateSecretRequest(

        @NotBlank
        @Size(max = 255)
        String name,

        @NotBlank
        @Base64Bytes(min = 28, max = 65_536, message = "encryptedBlob nije AES-GCM šifrat očekivane veličine")
        String encryptedBlob
) {
}
