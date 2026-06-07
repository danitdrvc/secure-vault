package com.securevault.audit.web;

import com.securevault.audit.domain.AuditAnchor;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Odgovor sa upisanim sidrom audit lanca ({@code POST /admin/audit/anchor}).
 */
public record AuditAnchorResponse(UUID id,
                                  long fromSeq,
                                  long toSeq,
                                  String headHash,
                                  String channel,
                                  String externalRef,
                                  OffsetDateTime createdAt) {

    public static AuditAnchorResponse from(AuditAnchor anchor) {
        return new AuditAnchorResponse(
                anchor.getId(),
                anchor.getFromSeq(),
                anchor.getToSeq(),
                anchor.getHeadHash(),
                anchor.getChannel(),
                anchor.getExternalRef(),
                anchor.getCreatedAt());
    }
}
