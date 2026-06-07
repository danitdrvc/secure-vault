package com.securevault.policy.web;

import com.securevault.policy.domain.SecurityPolicy;

/**
 * Pregled politike za KLIJENTSKU logiku ({@code GET /policy}, svaka važeća sesija). Izlaže samo
 * parametre koje klijent treba da zna, NE i tehnička podešavanja sesije/tokena (admin-only).
 *
 * <ul>
 *   <li>{@code minMasterPwLength} — klijent njime proverava da li je trenutna master lozinka
 *       kratka i traži promenu lozinke (re-deriv + {@code POST /auth/rotate-master}).</li>
 *   <li>{@code defaultRotationDays} — preporučeni rok rotacije nove tajne.</li>
 * </ul>
 */
public record ClientPolicyResponse(int minMasterPwLength, int defaultRotationDays) {

    public static ClientPolicyResponse from(SecurityPolicy policy) {
        return new ClientPolicyResponse(policy.getMinMasterPwLength(), policy.getDefaultRotationDays());
    }
}
