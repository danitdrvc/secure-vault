package com.securevault.audit.service;

/**
 * Rezultat provere integriteta audit hash-lanca ({@link AuditService#verify()}).
 *
 * @param valid          {@code true} ako je ceo lanac konzistentan (povezanost + heševi)
 * @param verifiedCount  broj pregledanih zapisa
 * @param brokenAtSeq    {@code seq} prvog nekonzistentnog zapisa, ili {@code null} ako je lanac ispravan
 */
public record AuditVerificationResult(boolean valid, long verifiedCount, Long brokenAtSeq) {

    static AuditVerificationResult ok(long verifiedCount) {
        return new AuditVerificationResult(true, verifiedCount, null);
    }

    static AuditVerificationResult broken(long verifiedCount, long brokenAtSeq) {
        return new AuditVerificationResult(false, verifiedCount, brokenAtSeq);
    }
}
