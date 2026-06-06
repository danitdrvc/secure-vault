package com.securevault.security;

import com.securevault.user.domain.Role;

import java.util.UUID;

/**
 * Principal koji {@link JwtCookieAuthenticationFilter} stavlja u {@code SecurityContext}
 * nakon validacije access tokena. Drži samo identitet i ulogu — nikad kripto materijal.
 */
public record AuthenticatedUser(UUID id, String username, Role role) {
}
