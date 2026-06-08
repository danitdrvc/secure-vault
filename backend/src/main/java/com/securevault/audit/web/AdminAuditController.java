package com.securevault.audit.web;

import com.securevault.audit.service.AuditAnchorService;
import com.securevault.audit.service.AuditService;
import com.securevault.common.error.NotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin uvid u imutabilni audit lanac (Faza 11). Saobraćaj stiže kroz gateway
 * ({@code /api/admin/audit/**} → {@code /admin/audit/**}). Sve rute zahtevaju ulogu {@code ADMIN}.
 *
 * <p><b>Append-only:</b> namerno postoje SAMO čitanje (verifikacija) i okidanje sidrenja — NEMA
 * PUT/PATCH/DELETE ruta nad {@code audit_log}. Zapise upisuje isključivo {@link AuditService#append}
 * kroz poslovne tokove; ne postoji javni način da se postojeći zapis izmeni ili obriše.
 */
@RestController
@RequestMapping("/admin/audit")
@PreAuthorize("hasRole('ADMIN')")
public class AdminAuditController {

    private final AuditService auditService;
    private final AuditAnchorService auditAnchorService;

    public AdminAuditController(AuditService auditService, AuditAnchorService auditAnchorService) {
        this.auditService = auditService;
        this.auditAnchorService = auditAnchorService;
    }

    /** Poslednjih 100 zapisa lanca (najnoviji prvi) — za admin pregled u UI-ju. */
    @GetMapping
    public List<AuditEntryResponse> list() {
        return auditService.recent().stream()
                .map(AuditEntryResponse::from)
                .toList();
    }

    /** Proverava integritet celog hash-lanca (povezanost + preračunati heševi). */
    @GetMapping("/verify")
    public AuditVerificationResponse verify() {
        return AuditVerificationResponse.from(auditService.verify());
    }

    /** Poslednjih 20 upisanih sidara (najnovije prvo) — za admin pregled u UI-ju. */
    @GetMapping("/anchors")
    public List<AuditAnchorResponse> anchors() {
        return auditAnchorService.recentAnchors().stream()
                .map(AuditAnchorResponse::from)
                .toList();
    }

    /**
     * Ručno sidri trenutni vrh lanca (uz periodični {@code @Scheduled} posao). {@code 404} ako
     * nema novih zapisa za sidrenje.
     */
    @PostMapping("/anchor")
    @ResponseStatus(HttpStatus.CREATED)
    public AuditAnchorResponse anchor() {
        return auditAnchorService.anchorHead()
                .map(AuditAnchorResponse::from)
                .orElseThrow(() -> new NotFoundException("Nema novih audit zapisa za sidrenje."));
    }
}
