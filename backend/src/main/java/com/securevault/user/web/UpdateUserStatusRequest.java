package com.securevault.user.web;

import com.securevault.user.domain.UserStatus;
import jakarta.validation.constraints.NotNull;

/**
 * Telo zahteva za admin promenu stanja naloga ({@code PATCH /admin/users/{id}/status}).
 *
 * <p>Admin SAMO aktivira/deaktivira nalog (DEVELOPMENT_PLAN Faza 8) — zato su jedine dozvoljene
 * ciljne vrednosti {@code ACTIVE} i {@code DEACTIVATED}. {@code FROZEN} je rezervisan za
 * automatski honeypot okidač (Faza 10) i ne postavlja se ručno preko ovog endpointa; servis
 * odbija svaku drugu vrednost.
 */
public record UpdateUserStatusRequest(

        @NotNull(message = "status je obavezan")
        UserStatus status
) {
}
