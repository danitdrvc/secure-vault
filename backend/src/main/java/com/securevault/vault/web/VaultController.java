package com.securevault.vault.web;

import com.securevault.security.AuthenticatedUser;
import com.securevault.vault.service.VaultService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Vault CRUD endpointi (Faza 6). Saobraćaj stiže kroz gateway ({@code /api/vault/**} →
 * {@code /vault/**}). Sve rute zahtevaju važeću sesiju (SecurityConfig: {@code anyRequest
 * .authenticated}); identitet korisnika dolazi iz access tokena (principal), ne iz tela zahteva.
 *
 * <p>Server vidi samo šifrat — enkripcija/dekripcija je isključivo na klijentu.
 */
@RestController
@RequestMapping("/vault/secrets")
public class VaultController {

    private final VaultService vaultService;

    public VaultController(VaultService vaultService) {
        this.vaultService = vaultService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public SecretSummaryResponse create(@AuthenticationPrincipal AuthenticatedUser principal,
                                        @Valid @RequestBody CreateSecretRequest request) {
        return vaultService.create(principal.id(), request);
    }

    @GetMapping
    public List<SecretSummaryResponse> list(@AuthenticationPrincipal AuthenticatedUser principal) {
        return vaultService.list(principal.id());
    }

    @GetMapping("/{id}")
    public SecretDetailResponse get(@AuthenticationPrincipal AuthenticatedUser principal,
                                    @PathVariable UUID id) {
        return vaultService.get(principal.id(), id);
    }

    @PutMapping("/{id}")
    public SecretSummaryResponse update(@AuthenticationPrincipal AuthenticatedUser principal,
                                        @PathVariable UUID id,
                                        @Valid @RequestBody UpdateSecretRequest request) {
        return vaultService.update(principal.id(), id, request);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal AuthenticatedUser principal,
                       @PathVariable UUID id) {
        vaultService.delete(principal.id(), id);
    }

    /**
     * Lista primaoca tajne (vlasnik-only). Vlasnik je koristi pre rotacije da bi pribavio javne
     * ključeve svih primaoca i uvio nov {@code secretKey} ka svakome.
     */
    @GetMapping("/{id}/access")
    public List<SecretAccessResponse> access(@AuthenticationPrincipal AuthenticatedUser principal,
                                             @PathVariable UUID id) {
        return vaultService.listAccess(principal.id(), id);
    }

    /**
     * Rotacija {@code secretKey}-a (Faza 8) — nov ključ + re-šifrovan blob + re-wrap ka svim
     * primaocima. Samo vlasnik; {@code wrappedKeys} mora pokriti tačno sve postojeće primaoce.
     * Stara {@code wrapped_secret_key} posle ovoga ne otvara novi blob.
     */
    @PostMapping("/{id}/rotate")
    public SecretSummaryResponse rotate(@AuthenticationPrincipal AuthenticatedUser principal,
                                        @PathVariable UUID id,
                                        @Valid @RequestBody RotateSecretRequest request) {
        return vaultService.rotate(principal.id(), id, request);
    }

    /**
     * Deli tajnu sa primaocem (Faza 7). SAMO uloga {@code TEAM_LEAD} ({@code @PreAuthorize});
     * {@code Developer} dobija {@code 403}. Server prima već uvijen {@code wrappedSecretKey} ka
     * primaocu — {@code encryptedBlob} se ne dira (envelope deljenje, zero-knowledge očuvan).
     */
    @PostMapping("/{id}/share")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('TEAM_LEAD')")
    public ShareResponse share(@AuthenticationPrincipal AuthenticatedUser principal,
                               @PathVariable UUID id,
                               @Valid @RequestBody ShareSecretRequest request) {
        return vaultService.share(principal.id(), id, request);
    }
}
