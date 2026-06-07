package com.securevault.policy.web;

import com.securevault.policy.domain.SecurityPolicy;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Pun pregled aktivne politike za admina ({@code GET/PATCH /admin/policy}). Sadrži sve
 * podesive parametre, ko ih je poslednji menjao i kada.
 */
public record PolicyResponse(
        UUID id,
        int minMasterPwLength,
        int defaultRotationDays,
        int accessTokenTtlSec,
        int refreshTokenTtlSec,
        int sessionMaxTtlSec,
        boolean honeypotEndpoint,
        UUID updatedById,
        OffsetDateTime updatedAt) {

    public static PolicyResponse from(SecurityPolicy policy) {
        return new PolicyResponse(
                policy.getId(),
                policy.getMinMasterPwLength(),
                policy.getDefaultRotationDays(),
                policy.getAccessTokenTtlSec(),
                policy.getRefreshTokenTtlSec(),
                policy.getSessionMaxTtlSec(),
                policy.isHoneypotEndpoint(),
                policy.getUpdatedById(),
                policy.getUpdatedAt());
    }
}
