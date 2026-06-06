package com.securevault.audit.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Sidro audit lanca — periodično "zapečaćivanje" vrha hash-lanca u spoljni kanal
 * (email / s3 / chain). Mapira se na {@code audit_anchor}.
 */
@Entity
@Table(name = "audit_anchor")
public class AuditAnchor {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "from_seq", nullable = false)
    private long fromSeq;

    @Column(name = "to_seq", nullable = false)
    private long toSeq;

    /** Vrh lanca u trenutku sidrenja. */
    @Column(name = "head_hash", nullable = false, length = 64)
    private String headHash;

    /** 'email' | 's3' | 'chain'. */
    @Column(name = "channel", nullable = false, length = 32)
    private String channel;

    /** Npr. tx hash / message id. */
    @Column(name = "external_ref", length = 255)
    private String externalRef;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public long getFromSeq() {
        return fromSeq;
    }

    public void setFromSeq(long fromSeq) {
        this.fromSeq = fromSeq;
    }

    public long getToSeq() {
        return toSeq;
    }

    public void setToSeq(long toSeq) {
        this.toSeq = toSeq;
    }

    public String getHeadHash() {
        return headHash;
    }

    public void setHeadHash(String headHash) {
        this.headHash = headHash;
    }

    public String getChannel() {
        return channel;
    }

    public void setChannel(String channel) {
        this.channel = channel;
    }

    public String getExternalRef() {
        return externalRef;
    }

    public void setExternalRef(String externalRef) {
        this.externalRef = externalRef;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }
}
