package com.securevault.policy.service;

import com.securevault.audit.service.AuditService;
import com.securevault.policy.domain.SecurityPolicy;
import com.securevault.policy.repository.SecurityPolicyRepository;
import com.securevault.policy.web.ClientPolicyResponse;
import com.securevault.policy.web.PolicyResponse;
import com.securevault.policy.web.UpdatePolicyRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Poslovna logika sigurnosne politike (Faza 8). U svakom trenutku tačno jedan red je aktivan;
 * admin ga menja preko {@code PATCH /admin/policy}, a klijent čita podskup preko {@code GET /policy}.
 *
 * <p>TTL-ove iz politike u runtime-u čita {@code TokenService} (rotacija/cap sesije), pa izmena
 * ovde odmah utiče na sledeće izdate/rotirane tokene — bez restarta.
 */
@Service
public class SecurityPolicyService {

    private final SecurityPolicyRepository policyRepository;
    private final AuditService auditService;

    public SecurityPolicyService(SecurityPolicyRepository policyRepository, AuditService auditService) {
        this.policyRepository = policyRepository;
        this.auditService = auditService;
    }

    /** Pun pregled aktivne politike (admin). */
    @Transactional(readOnly = true)
    public PolicyResponse adminView() {
        return PolicyResponse.from(activePolicy());
    }

    /** Klijentski podskup politike (svaka važeća sesija). */
    @Transactional(readOnly = true)
    public ClientPolicyResponse clientView() {
        return ClientPolicyResponse.from(activePolicy());
    }

    /**
     * Admin izmena politike (PATCH): primenjuje SAMO ne-null polja, beleži ko je menjao i
     * audit zapis. Vraća pun pregled posle izmene.
     */
    @Transactional
    public PolicyResponse update(UUID adminId, UpdatePolicyRequest request) {
        SecurityPolicy policy = activePolicy();

        if (request.minMasterPwLength() != null) {
            policy.setMinMasterPwLength(request.minMasterPwLength());
        }
        if (request.defaultRotationDays() != null) {
            policy.setDefaultRotationDays(request.defaultRotationDays());
        }
        if (request.accessTokenTtlSec() != null) {
            policy.setAccessTokenTtlSec(request.accessTokenTtlSec());
        }
        if (request.refreshTokenTtlSec() != null) {
            policy.setRefreshTokenTtlSec(request.refreshTokenTtlSec());
        }
        if (request.sessionMaxTtlSec() != null) {
            policy.setSessionMaxTtlSec(request.sessionMaxTtlSec());
        }
        if (request.honeypotEndpoint() != null) {
            policy.setHoneypotEndpoint(request.honeypotEndpoint());
        }
        policy.setUpdatedById(adminId);

        SecurityPolicy saved = policyRepository.save(policy);
        auditService.record("POLICY_UPDATED", adminId, "security_policy/" + saved.getId(), "{}");
        return PolicyResponse.from(saved);
    }

    private SecurityPolicy activePolicy() {
        return policyRepository.findFirstByActiveTrue()
                .orElseThrow(() -> new IllegalStateException("Nema aktivne security_policy."));
    }
}
