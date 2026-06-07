package com.securevault.audit.web;

import com.securevault.audit.service.AuditVerificationResult;

/**
 * Odgovor provere integriteta audit lanca ({@code GET /admin/audit/verify}).
 *
 * @param valid         {@code true} ako je ceo lanac netaknut
 * @param verifiedCount broj pregledanih zapisa
 * @param brokenAtSeq   {@code seq} prvog nekonzistentnog zapisa, ili {@code null} ako je lanac ispravan
 */
public record AuditVerificationResponse(boolean valid, long verifiedCount, Long brokenAtSeq) {

    public static AuditVerificationResponse from(AuditVerificationResult result) {
        return new AuditVerificationResponse(result.valid(), result.verifiedCount(), result.brokenAtSeq());
    }
}
