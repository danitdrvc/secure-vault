package com.securevault.vault.service;

import com.securevault.audit.service.AuditService;
import com.securevault.common.error.ConflictException;
import com.securevault.common.error.ForbiddenException;
import com.securevault.common.error.NotFoundException;
import com.securevault.common.error.ValidationException;
import com.securevault.user.repository.UserRepository;
import com.securevault.vault.domain.Secret;
import com.securevault.vault.domain.SecretAccess;
import com.securevault.vault.repository.SecretAccessRepository;
import com.securevault.vault.repository.SecretRepository;
import com.securevault.vault.web.CreateSecretRequest;
import com.securevault.vault.web.RotateSecretRequest;
import com.securevault.vault.web.SecretAccessResponse;
import com.securevault.vault.web.SecretDetailResponse;
import com.securevault.vault.web.SecretSummaryResponse;
import com.securevault.vault.web.ShareResponse;
import com.securevault.vault.web.ShareSecretRequest;
import com.securevault.vault.web.UpdateSecretRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
    private final UserRepository userRepository;
    private final AuditService auditService;

    public VaultService(SecretRepository secretRepository,
                        SecretAccessRepository secretAccessRepository,
                        UserRepository userRepository,
                        AuditService auditService) {
        this.secretRepository = secretRepository;
        this.secretAccessRepository = secretAccessRepository;
        this.userRepository = userRepository;
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
        // Opcioni rok rotacije (null = bez rotacije). Klijent pri otvaranju poredi
        // rotated_at + rotation_days sa sada i prikazuje upozorenje o isteku (Faza 8).
        secret.setRotationDays(request.rotationDays());
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

    /**
     * Lista korisnika koji imaju pristup tajni (vlasnik-only). Vlasnik je koristi pre rotacije
     * da bi pribavio javne ključeve svih primaoca i uvio nov {@code secretKey} ka svakome.
     */
    @Transactional(readOnly = true)
    public List<SecretAccessResponse> listAccess(UUID userId, UUID secretId) {
        Secret secret = requireVisibleSecret(secretId);
        requireOwner(secret, userId);
        return secretAccessRepository.findBySecretId(secretId).stream()
                .map(SecretAccessResponse::from)
                .toList();
    }

    /**
     * Rotacija {@code secretKey}-a (Faza 8). Vlasnik na klijentu generiše NOV {@code secretKey},
     * re-šifruje blob i uvija novi ključ ka SVIM trenutnim primaocima. Server: zameni
     * {@code encrypted_blob}, osveži {@code rotated_at}, i za svaki {@code secret_access} red
     * upiše novi {@code wrapped_secret_key}. Stara {@code wrapped_secret_key} time prestaje da
     * otvara novi blob (nov ključ, nov šifrat).
     *
     * <p>Invarijanta: {@code wrappedKeys} mora pokriti TAČNO skup postojećih primaoca — nijedan
     * višak, nijedan manjak — inače bi neko izgubio pristup ({@code 400}).
     */
    @Transactional
    public SecretSummaryResponse rotate(UUID userId, UUID secretId, RotateSecretRequest request) {
        Secret secret = requireVisibleSecret(secretId);
        requireOwner(secret, userId);

        List<SecretAccess> accesses = secretAccessRepository.findBySecretId(secretId);
        Base64.Decoder decoder = Base64.getDecoder();

        Map<UUID, String> incoming = new HashMap<>();
        for (RotateSecretRequest.WrappedKeyEntry entry : request.wrappedKeys()) {
            if (incoming.put(entry.userId(), entry.wrappedSecretKey()) != null) {
                throw new ValidationException("Dvostruki wrappedKey za istog primaoca.");
            }
        }
        if (incoming.size() != accesses.size()) {
            throw new ValidationException("Rotacija mora re-wrap-ovati tačno sve primaoce tajne.");
        }

        for (SecretAccess access : accesses) {
            String wrapped = incoming.get(access.getUserId());
            if (wrapped == null) {
                throw new ValidationException("Nedostaje wrappedKey za primaoca " + access.getUserId() + ".");
            }
            access.setWrappedSecretKey(decoder.decode(wrapped));
        }
        secretAccessRepository.saveAll(accesses);

        secret.setEncryptedBlob(decoder.decode(request.encryptedBlob()));
        secret.setRotatedAt(OffsetDateTime.now());
        Secret saved = secretRepository.save(secret);

        auditService.record("SECRET_ROTATED", userId, "secrets/" + secretId, "{}");
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

    /**
     * Deli tajnu sa primaocem (Faza 7) — envelope re-wrap. Onaj ko deli MORA imati pristup
     * tajni (svoj {@code secret_access} red), jer samo tako može na klijentu da otvori i ponovo
     * uvije {@code secretKey}. Server prima već uvijen {@code wrappedSecretKey} ka primaocu i
     * upisuje nov pristupni red — {@code encryptedBlob} se NE menja (veliki blob se nikad ne
     * re-šifruje). Ulogu {@code TEAM_LEAD} proverava {@code @PreAuthorize} na kontroleru.
     */
    @Transactional
    public ShareResponse share(UUID sharerId, UUID secretId, ShareSecretRequest request) {
        Secret secret = requireVisibleSecret(secretId);

        // Onaj ko deli mora i sam imati pristup (vlasnik ili raniji primalac) — inače ne poseduje
        // secretKey i deljenje ne bi imalo smisla (server to ne može kriptografski da proveri,
        // ali pristupni red je nužan uslov).
        if (secretAccessRepository.findBySecretIdAndUserId(secretId, sharerId).isEmpty()) {
            throw new ForbiddenException("Nemate pristup ovoj tajni.");
        }

        UUID recipientId = request.recipientId();
        if (!userRepository.existsById(recipientId)) {
            throw new NotFoundException("Korisnik ne postoji.");
        }
        if (secretAccessRepository.findBySecretIdAndUserId(secretId, recipientId).isPresent()) {
            throw new ConflictException("Tajna je već podeljena sa ovim korisnikom.");
        }

        SecretAccess access = new SecretAccess();
        access.setSecretId(secretId);
        access.setUserId(recipientId);
        access.setWrappedSecretKey(Base64.getDecoder().decode(request.wrappedSecretKey()));
        access.setGrantedById(sharerId);
        SecretAccess saved = secretAccessRepository.save(access);

        auditService.record("SECRET_SHARED", sharerId, "secrets/" + secretId,
                "{\"recipientId\":\"" + recipientId + "\"}");
        return ShareResponse.from(saved);
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
