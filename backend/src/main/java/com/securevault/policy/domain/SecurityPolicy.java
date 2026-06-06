package com.securevault.policy.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Sigurnosna politika koju definiše admin. Mapira se na {@code security_policy}.
 * U svakom trenutku tačno jedan red je {@code isActive = true}.
 */
@Entity
@Table(name = "security_policy")
public class SecurityPolicy {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "min_master_pw_length", nullable = false)
    private int minMasterPwLength = 12;

    @Column(name = "default_rotation_days", nullable = false)
    private int defaultRotationDays = 90;

    @Column(name = "access_token_ttl_sec", nullable = false)
    private int accessTokenTtlSec = 300;

    @Column(name = "refresh_token_ttl_sec", nullable = false)
    private int refreshTokenTtlSec = 3600;

    /** Apsolutni cap trajanja sesije od logina. */
    @Column(name = "session_max_ttl_sec", nullable = false)
    private int sessionMaxTtlSec = 1800;

    /** Admin pali ranjivi test-endpoint (honeypot). */
    @Column(name = "honeypot_endpoint", nullable = false)
    private boolean honeypotEndpoint = false;

    @Column(name = "is_active", nullable = false)
    private boolean active = true;

    @Column(name = "updated_by_id")
    private UUID updatedById;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public int getMinMasterPwLength() {
        return minMasterPwLength;
    }

    public void setMinMasterPwLength(int minMasterPwLength) {
        this.minMasterPwLength = minMasterPwLength;
    }

    public int getDefaultRotationDays() {
        return defaultRotationDays;
    }

    public void setDefaultRotationDays(int defaultRotationDays) {
        this.defaultRotationDays = defaultRotationDays;
    }

    public int getAccessTokenTtlSec() {
        return accessTokenTtlSec;
    }

    public void setAccessTokenTtlSec(int accessTokenTtlSec) {
        this.accessTokenTtlSec = accessTokenTtlSec;
    }

    public int getRefreshTokenTtlSec() {
        return refreshTokenTtlSec;
    }

    public void setRefreshTokenTtlSec(int refreshTokenTtlSec) {
        this.refreshTokenTtlSec = refreshTokenTtlSec;
    }

    public int getSessionMaxTtlSec() {
        return sessionMaxTtlSec;
    }

    public void setSessionMaxTtlSec(int sessionMaxTtlSec) {
        this.sessionMaxTtlSec = sessionMaxTtlSec;
    }

    public boolean isHoneypotEndpoint() {
        return honeypotEndpoint;
    }

    public void setHoneypotEndpoint(boolean honeypotEndpoint) {
        this.honeypotEndpoint = honeypotEndpoint;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public UUID getUpdatedById() {
        return updatedById;
    }

    public void setUpdatedById(UUID updatedById) {
        this.updatedById = updatedById;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }
}
