package com.securevault.policy.web;

import com.securevault.policy.service.SecurityPolicyService;
import com.securevault.security.AuthenticatedUser;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpointi sigurnosne politike (Faza 8). Saobraćaj stiže kroz gateway
 * ({@code /api/policy}, {@code /api/admin/policy}).
 *
 * <ul>
 *   <li>{@code GET /policy} — klijentski podskup (min dužina lozinke, rok rotacije); svaka
 *       važeća sesija. Klijent njime vodi scenario „povećana min dužina" → promena lozinke.</li>
 *   <li>{@code GET /admin/policy}, {@code PATCH /admin/policy} — pun pregled/izmena; SAMO admin
 *       ({@code @PreAuthorize}).</li>
 * </ul>
 */
@RestController
public class PolicyController {

    private final SecurityPolicyService policyService;

    public PolicyController(SecurityPolicyService policyService) {
        this.policyService = policyService;
    }

    @GetMapping("/policy")
    public ClientPolicyResponse clientPolicy() {
        return policyService.clientView();
    }

    @GetMapping("/admin/policy")
    @PreAuthorize("hasRole('ADMIN')")
    public PolicyResponse adminPolicy() {
        return policyService.adminView();
    }

    @PatchMapping("/admin/policy")
    @PreAuthorize("hasRole('ADMIN')")
    public PolicyResponse updatePolicy(@AuthenticationPrincipal AuthenticatedUser admin,
                                       @Valid @RequestBody UpdatePolicyRequest request) {
        return policyService.update(admin.id(), request);
    }
}
