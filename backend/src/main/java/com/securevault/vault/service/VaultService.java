package com.securevault.vault.service;

import com.securevault.audit.service.AuditService;
import com.securevault.common.error.ForbiddenException;
import com.securevault.common.error.NotFoundException;
import com.securevault.vault.domain.Secret;
import com.securevault.vault.domain.SecretAccess;
import com.securevault.vault.repository.SecretAccessRepository;
import com.securevault.vault.repository.SecretRepository;
import com.securevault.vault.web.CreateSecretRequest;
import com.securevault.vault.web.SecretDetailResponse;
import com.securevault.vault.web.SecretSummaryResponse;
import com.securevault.vault.web.UpdateSecretRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Poslovna logika vault-a (Faza 6) — CRUD nad tajnama.
 *
 * <p><b>Zero-knowledge:</b> server prima i vraća isključivo šifrat ({@code encryptedBlob},
 * {@code wrappedSecretKey}). Enkripcija/dekripcija sadržaja se dešava SAMO na klijentu; ovde se
 * radi samo skladištenje bajtova, kontrola pristupa i audit. Nijedan endpoint ne vraća plaintext.
 *
 * <p><b>Honeytokeni</b> ({@code is_honeytoken = true}) su nevidljivi regularnom API-ju: lista ih
 * izostavlja, a direktan dohvat vraća {@code 404} (kao da ne postoje). Pravi okidač (zamrzavanje
 * naloga + alarm) dolazi u Fazi 10.
 */
@Service
public class VaultService {

    private final SecretRepository secretRepository;
    private final SecretAccessRepository secretAccessRepository;
    private final AuditService auditService;

    public VaultService(SecretRepository secretRepository,
                        SecretAccessRepository secretAccessRepository,
                        AuditService auditService) {
        this.secretRepository = secretRepository;
        this.secretAccessRepository = secretAccessRepository;
        this.auditService = auditService;
    }

    /**
     * Kreira tajnu i vlasnikov pristupni red. Tajna se uvek upisuje kao {@code honeytoken=false}
     * (honeytokene seed-uje sistem, ne korisnik).
     */
    @Transactional
    public SecretSummaryResponse create(UUID ownerId, CreateSecretRequest request) {
        Base64.Decoder decoder = Base64.getDecoder();

        Secret secret = new Secret();
        secret.setOwnerId(ownerId);
        secret.setName(request.name());
        secret.setEncryptedBlob(decoder.decode(request.encryptedBlob()));
        secret.setHoneytoken(false);
        Secret saved = secretRepository.save(secret);

        SecretAccess access = new SecretAccess();
        access.setSecretId(saved.getId());
        access.setUserId(ownerId);
        access.setWrappedSecretKey(decoder.decode(request.wrappedSecretKey()));
        access.setGrantedById(ownerId);
        secretAccessRepository.save(access);

        auditService.record("SECRET_CREATED", ownerId, "secrets/" + saved.getId(), "{}");
        return SecretSummaryResponse.from(saved);
    }

    /** Metapodaci svih tajni kojima korisnik ima pristup (bez honeytokena). */
    @Transactional(readOnly = true)
    public List<SecretSummaryResponse> list(UUID userId) {
        return secretRepository.findAccessibleNonHoneytoken(userId).stream()
                .map(SecretSummaryResponse::from)
                .toList();
    }

    /**
     * Pun (šifrovan) sadržaj tajne za korisnika. Korisnik bez pristupnog reda dobija {@code 403};
     * honeytoken/nepostojeća tajna → {@code 404}.
     */
    @Transactional(readOnly = true)
    public SecretDetailResponse get(UUID userId, UUID secretId) {
        Secret secret = requireVisibleSecret(secretId);
        SecretAccess access = secretAccessRepository.findBySecretIdAndUserId(secretId, userId)
                .orElseThrow(() -> new ForbiddenException("Nemate pristup ovoj tajni."));
        return SecretDetailResponse.from(secret, access.getWrappedSecretKey());
    }

    /**
     * Menja {@code name} i {@code encryptedBlob}. Samo vlasnik sme da menja. {@code secretKey}
     * (a time i {@code wrapped_secret_key}) ostaje nepromenjen — klijent re-šifruje istim ključem.
     */
    @Transactional
    public SecretSummaryResponse update(UUID userId, UUID secretId, UpdateSecretRequest request) {
        Secret secret = requireVisibleSecret(secretId);
        requireOwner(secret, userId);

        secret.setName(request.name());
        secret.setEncryptedBlob(Base64.getDecoder().decode(request.encryptedBlob()));
        Secret saved = secretRepository.save(secret);

        auditService.record("SECRET_UPDATED", userId, "secrets/" + secretId, "{}");
        return SecretSummaryResponse.from(saved);
    }

    /** Briše tajnu (i sve njene pristupne redove). Samo vlasnik sme da briše. */
    @Transactional
    public void delete(UUID userId, UUID secretId) {
        Secret secret = requireVisibleSecret(secretId);
        requireOwner(secret, userId);

        secretAccessRepository.deleteBySecretId(secretId);
        secretRepository.delete(secret);

        auditService.record("SECRET_DELETED", userId, "secrets/" + secretId, "{}");
    }

    /** Učitava tajnu; honeytoken i nepostojeća tajna se jednako tretiraju kao {@code 404}. */
    private Secret requireVisibleSecret(UUID secretId) {
        Secret secret = secretRepository.findById(secretId)
                .orElseThrow(() -> new NotFoundException("Tajna ne postoji."));
        if (secret.isHoneytoken()) {
            // Honeytoken se ne sme otkriti regularnom API-ju (Faza 10 dodaje okidač pri pristupu).
            throw new NotFoundException("Tajna ne postoji.");
        }
        return secret;
    }

    private void requireOwner(Secret secret, UUID userId) {
        if (!secret.getOwnerId().equals(userId)) {
            throw new ForbiddenException("Samo vlasnik može da menja ili briše tajnu.");
        }
    }
}
