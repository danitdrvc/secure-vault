package com.securevault.user.web;

import com.securevault.user.domain.Role;
import com.securevault.user.domain.UserStatus;

import java.util.UUID;

/**
 * Odgovor registracije — samo javni metapodaci naloga. NIKAD ne vraća kripto materijal
 * (kdf, authHash, encUsk, encPrivateKey, publicKey).
 */
public record RegisterResponse(
        UUID id,
        String username,
        String email,
        Role role,
        UserStatus status
) {
}
