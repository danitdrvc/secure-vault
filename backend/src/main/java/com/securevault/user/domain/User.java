package com.securevault.user.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Korisnik. Mapira se na tabelu {@code users} (DDL: V1__init.sql).
 * Zero-knowledge artefakti ({@code encUsk}, {@code encPrivateKey}) i {@code authHash}
 * su za server neprozirni bajtovi — server ih nikad ne dešifruje ni ne generiše.
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "username", nullable = false, unique = true, length = 64)
    private String username;

    @Column(name = "email", nullable = false, unique = true, length = 255)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 16)
    private Role role = Role.DEVELOPER;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private UserStatus status = UserStatus.ACTIVE;

    /** KDF salt — klijent ga koristi da reprodukuje master key. */
    @Column(name = "kdf_salt", nullable = false)
    private byte[] kdfSalt;

    @Column(name = "kdf_iterations", nullable = false)
    private int kdfIterations = 600_000;

    /** bcrypt(authKey) — server NIKAD ne vidi authKey ni master lozinku. */
    @Column(name = "auth_hash", nullable = false, length = 100)
    private String authHash;

    /** AES-256-GCM(KEK, USK), uključuje nonce. */
    @Column(name = "enc_usk", nullable = false)
    private byte[] encUsk;

    /** RSA javni ključ (SPKI, plaintext). */
    @Column(name = "public_key", nullable = false)
    private byte[] publicKey;

    /** AES-256-GCM(USK, privateKey PKCS8), uključuje nonce. */
    @Column(name = "enc_private_key", nullable = false)
    private byte[] encPrivateKey;

    /** TOTP tajna šifrovana server-side ključem (izvan zero-knowledge domena). */
    @Column(name = "totp_secret_enc")
    private byte[] totpSecretEnc;

    @Column(name = "totp_enabled", nullable = false)
    private boolean totpEnabled = false;

    @Column(name = "oidc_subject", unique = true, length = 255)
    private String oidcSubject;

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

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public UserStatus getStatus() {
        return status;
    }

    public void setStatus(UserStatus status) {
        this.status = status;
    }

    public byte[] getKdfSalt() {
        return kdfSalt;
    }

    public void setKdfSalt(byte[] kdfSalt) {
        this.kdfSalt = kdfSalt;
    }

    public int getKdfIterations() {
        return kdfIterations;
    }

    public void setKdfIterations(int kdfIterations) {
        this.kdfIterations = kdfIterations;
    }

    public String getAuthHash() {
        return authHash;
    }

    public void setAuthHash(String authHash) {
        this.authHash = authHash;
    }

    public byte[] getEncUsk() {
        return encUsk;
    }

    public void setEncUsk(byte[] encUsk) {
        this.encUsk = encUsk;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getEncPrivateKey() {
        return encPrivateKey;
    }

    public void setEncPrivateKey(byte[] encPrivateKey) {
        this.encPrivateKey = encPrivateKey;
    }

    public byte[] getTotpSecretEnc() {
        return totpSecretEnc;
    }

    public void setTotpSecretEnc(byte[] totpSecretEnc) {
        this.totpSecretEnc = totpSecretEnc;
    }

    public boolean isTotpEnabled() {
        return totpEnabled;
    }

    public void setTotpEnabled(boolean totpEnabled) {
        this.totpEnabled = totpEnabled;
    }

    public String getOidcSubject() {
        return oidcSubject;
    }

    public void setOidcSubject(String oidcSubject) {
        this.oidcSubject = oidcSubject;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }
}
