package com.securevault.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Append-only zapis revizije. Mapira se na {@code audit_log}.
 * {@code hash} = SHA-256(canonical(payload) || prevHash) gradi linearni hash-lanac
 * (Faza 11). Nikad se ne UPDATE-uje ni DELETE-uje.
 *
 * <p>{@code createdAt} se postavlja EKSPLICITNO u {@code AuditService.append} (a ne preko
 * {@code @CreationTimestamp}) jer je deo heširanog sadržaja: vrednost mora biti poznata PRE
 * računanja heša i mora se identično reprodukovati pri {@code verifyChain()}. Postavlja se na
 * UTC skraćeno na mikrosekunde (preciznost {@code timestamptz}-a) da round-trip kroz bazu bude
 * bit-identičan.
 */
@Entity
@Table(name = "audit_log")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    /** Monotono rastući redosled — DB ga dodeljuje (bigserial). */
    @Column(name = "seq", insertable = false, updatable = false)
    private Long seq;

    @Column(name = "actor_id")
    private UUID actorId;

    @Column(name = "action", nullable = false, length = 32)
    private String action;

    @Column(name = "resource", length = 255)
    private String resource;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "metadata", nullable = false, columnDefinition = "jsonb")
    private String metadata = "{}";

    @Column(name = "prev_hash", nullable = false, length = 64)
    private String prevHash;

    @Column(name = "hash", nullable = false, unique = true, length = 64)
    private String hash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Long getSeq() {
        return seq;
    }

    public UUID getActorId() {
        return actorId;
    }

    public void setActorId(UUID actorId) {
        this.actorId = actorId;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getMetadata() {
        return metadata;
    }

    public void setMetadata(String metadata) {
        this.metadata = metadata;
    }

    public String getPrevHash() {
        return prevHash;
    }

    public void setPrevHash(String prevHash) {
        this.prevHash = prevHash;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
