package com.securevault.user.web;

import com.securevault.security.AuthenticatedUser;
import com.securevault.user.service.UserService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * Admin endpointi nad nalozima (Faza 8). Saobraćaj stiže kroz gateway ({@code /api/admin/**} →
 * {@code /admin/**}). SVE rute zahtevaju ulogu {@code ADMIN} ({@code @PreAuthorize}); ostali
 * autentikovani korisnici dobijaju {@code 403}.
 *
 * <p>Admin upravlja samo <i>statusom</i> naloga (aktivacija/deaktivacija) — NIKAD tajnama ni
 * kripto materijalom; vault ostaje zero-knowledge i za admina.
 */
@RestController
@RequestMapping("/admin/users")
@PreAuthorize("hasRole('ADMIN')")
public class AdminUserController {

    private final UserService userService;

    public AdminUserController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Aktivira ili deaktivira nalog. Deaktiviran nalog ne može da se uloguje
     * ({@code AuthService.step1} vraća {@code 403} za svaki status ≠ {@code ACTIVE}).
     */
    @PatchMapping("/{id}/status")
    public AdminUserResponse updateStatus(@AuthenticationPrincipal AuthenticatedUser admin,
                                          @PathVariable UUID id,
                                          @Valid @RequestBody UpdateUserStatusRequest request) {
        return userService.updateStatus(admin.id(), id, request.status());
    }
}
