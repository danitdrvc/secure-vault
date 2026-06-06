package com.securevault.auth.web;

import com.securevault.common.validation.Base64Bytes;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Prvi korak logina: korisničko ime + {@code authKey} (HKDF "vault-auth", 32 B, base64).
 * Server poredi {@code bcrypt(authKey)}; NIKAD ne vidi master lozinku ni KEK.
 */
public record LoginStep1Request(
        @NotBlank
        @Size(max = 64)
        String username,

        @NotBlank
        @Base64Bytes(min = 32, max = 32, message = "authKey mora biti tačno 32 bajta (base64)")
        String authKey
) {
}
