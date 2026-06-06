package com.securevault.vault.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import org.hibernate.annotations.CreationTimestamp;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Pristup tajni (deljenje). Mapira se na {@code secret_access}.
 * {@code wrappedSecretKey} = RSA-OAEP(secretKey, user.public_key) — samo vlasnik
 * privatnog ključa može da otvori tajnu.
 */
@Entity
@Table(name = "secret_access",
        uniqueConstraints = @UniqueConstraint(columnNames = {"secret_id", "user_id"}))
public class SecretAccess {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "secret_id", nullable = false)
    private UUID secretId;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "wrapped_secret_key", nullable = false)
    private byte[] wrappedSecretKey;

    @Column(name = "granted_by_id")
    private UUID grantedById;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public UUID getSecretId() {
        return secretId;
    }

    public void setSecretId(UUID secretId) {
        this.secretId = secretId;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public byte[] getWrappedSecretKey() {
        return wrappedSecretKey;
    }

    public void setWrappedSecretKey(byte[] wrappedSecretKey) {
        this.wrappedSecretKey = wrappedSecretKey;
    }

    public UUID getGrantedById() {
        return grantedById;
    }

    public void setGrantedById(UUID grantedById) {
        this.grantedById = grantedById;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }
}
