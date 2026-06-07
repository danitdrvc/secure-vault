package com.securevault.vault.web;

import com.securevault.common.validation.Base64Bytes;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;
import java.util.UUID;

/**
 * Telo zahteva za rotaciju samog {@code secretKey}-a (Faza 8). Za razliku od {@code PUT}
 * (isti ključ, nov blob), rotacija generiše NOV {@code secretKey} na klijentu, re-šifruje blob
 * i uvija novi ključ ka SVIM postojećim primaocima (envelope re-wrap). Stara
 * {@code wrapped_secret_key} time prestaje da otvara novi blob.
 *
 * <p>{@code wrappedKeys} mora pokriti TAČNO sve trenutne {@code secret_access} redove (uključujući
 * vlasnika) — inače bi neko izgubio pristup; servis to proverava i odbija nepotpun skup ({@code 400}).
 */
public record RotateSecretRequest(

        @NotBlank
        @Base64Bytes(min = 28, max = 65_536, message = "encryptedBlob nije AES-GCM šifrat očekivane veličine")
        String encryptedBlob,

        @NotEmpty(message = "wrappedKeys mora sadržati re-wrap za svakog primaoca")
        @Valid
        List<WrappedKeyEntry> wrappedKeys
) {

    /** Po-primalac uvijen novi {@code secretKey} (RSA-OAEP ka javnom ključu tog korisnika). */
    public record WrappedKeyEntry(

            @NotNull(message = "userId je obavezan")
            UUID userId,

            @NotBlank
            @Base64Bytes(min = 256, max = 256, message = "wrappedSecretKey mora biti RSA-OAEP-2048 šifrat (256 bajtova)")
            String wrappedSecretKey
    ) {
    }
}
