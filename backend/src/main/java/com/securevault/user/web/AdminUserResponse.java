package com.securevault.user.web;

import com.securevault.user.domain.Role;
import com.securevault.user.domain.User;
import com.securevault.user.domain.UserStatus;

import java.util.UUID;

/**
 * Pregled naloga za admin operacije. Sadrži samo neosetljive metapodatke — NIKAD kripto
 * materijal (auth_hash, enc_usk, enc_private_key, public_key) niti TOTP tajnu.
 */
public record AdminUserResponse(UUID id, String username, String email, Role role, UserStatus status) {

    public static AdminUserResponse from(User user) {
        return new AdminUserResponse(user.getId(), user.getUsername(), user.getEmail(),
                user.getRole(), user.getStatus());
    }
}
