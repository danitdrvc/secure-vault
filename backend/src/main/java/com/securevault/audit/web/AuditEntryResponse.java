package com.securevault.audit.web;

import com.securevault.audit.domain.AuditLog;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Jedan zapis audit lanca za admin pregled ({@code GET /admin/audit}). Sadrži samo metapodatke
 * revizije i heševe lanca — nikad osetljiv sadržaj tajni (vault ostaje zero-knowledge i za admina).
 */
public record AuditEntryResponse(long seq,
                                 String action,
                                 UUID actorId,
                                 String resource,
                                 String metadata,
                                 String prevHash,
                                 String hash,
                                 OffsetDateTime createdAt) {

    public static AuditEntryResponse from(AuditLog log) {
        return new AuditEntryResponse(
                log.getSeq(),
                log.getAction(),
                log.getActorId(),
                log.getResource(),
                log.getMetadata(),
                log.getPrevHash(),
                log.getHash(),
                log.getCreatedAt());
    }
}
