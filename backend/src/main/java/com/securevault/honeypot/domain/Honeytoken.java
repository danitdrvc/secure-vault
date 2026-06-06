package com.securevault.honeypot.domain;

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
 * Mamac (honeytoken) — izgleda kao realan resurs; svaki pristup je signal napada.
 * Mapira se na {@code honeytoken}.
 */
@Entity
@Table(name = "honeytoken")
public class Honeytoken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "label", nullable = false, length = 255)
    private String label;

    @Column(name = "fake_blob", nullable = false)
    private byte[] fakeBlob;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public byte[] getFakeBlob() {
        return fakeBlob;
    }

    public void setFakeBlob(byte[] fakeBlob) {
        this.fakeBlob = fakeBlob;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }
}
