package com.securevault.vault.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Tajna. Mapira se na tabelu {@code secrets}.
 * {@code encryptedBlob} = AES-256-GCM(secretKey, plaintext) + nonce — server skladišti
 * samo neprozirne bajtove; {@code name} je metapodatak (nije tajni sadržaj).
 */
@Entity
@Table(name = "secrets")
public class Secret {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "owner_id", nullable = false)
    private UUID ownerId;

    @Column(name = "name", nullable = false, length = 255)
    private String name;

    @Column(name = "encrypted_blob", nullable = false)
    private byte[] encryptedBlob;

    @Column(name = "is_honeytoken", nullable = false)
    private boolean honeytoken = false;

    /** null = bez rotacije. */
    @Column(name = "rotation_days")
    private Integer rotationDays;

    @Column(name = "rotated_at", nullable = false)
    private OffsetDateTime rotatedAt = OffsetDateTime.now();

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public UUID getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(UUID ownerId) {
        this.ownerId = ownerId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public byte[] getEncryptedBlob() {
        return encryptedBlob;
    }

    public void setEncryptedBlob(byte[] encryptedBlob) {
        this.encryptedBlob = encryptedBlob;
    }

    public boolean isHoneytoken() {
        return honeytoken;
    }

    public void setHoneytoken(boolean honeytoken) {
        this.honeytoken = honeytoken;
    }

    public Integer getRotationDays() {
        return rotationDays;
    }

    public void setRotationDays(Integer rotationDays) {
        this.rotationDays = rotationDays;
    }

    public OffsetDateTime getRotatedAt() {
        return rotatedAt;
    }

    public void setRotatedAt(OffsetDateTime rotatedAt) {
        this.rotatedAt = rotatedAt;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }
}
