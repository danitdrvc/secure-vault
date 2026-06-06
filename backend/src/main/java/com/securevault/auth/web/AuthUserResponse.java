package com.securevault.auth.web;

import com.securevault.user.domain.Role;
import com.securevault.user.domain.User;
import com.securevault.user.domain.UserStatus;

import java.util.UUID;

/** Javni metapodaci naloga (bez ikakvog kripto materijala). */
public record AuthUserResponse(UUID id, String username, String email, Role role, UserStatus status) {

    public static AuthUserResponse from(User user) {
        return new AuthUserResponse(user.getId(), user.getUsername(), user.getEmail(),
                user.getRole(), user.getStatus());
    }
}
