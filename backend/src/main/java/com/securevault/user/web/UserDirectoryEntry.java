package com.securevault.user.web;

import com.securevault.user.domain.Role;
import com.securevault.user.domain.User;

import java.util.UUID;

/**
 * Stavka imenika korisnika ({@code GET /users}). Služi da onaj ko deli tajnu (Faza 7) izabere
 * primaoca iz liste umesto da ručno unosi UUID. Sadrži samo neosetljive metapodatke
 * ({@code id}, {@code username}, {@code role}) — nikad email, status ni kripto materijal.
 */
public record UserDirectoryEntry(UUID id, String username, Role role) {

    public static UserDirectoryEntry from(User user) {
        return new UserDirectoryEntry(user.getId(), user.getUsername(), user.getRole());
    }
}
