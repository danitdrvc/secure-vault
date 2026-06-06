package com.securevault.audit.service;

import com.securevault.audit.domain.AuditLog;
import com.securevault.audit.repository.AuditLogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Upisuje append-only audit zapise.
 *
 * <p><b>Faza 3 (privremeno):</b> koristi STUB lanac — {@code prevHash = "GENESIS"} za svaki
 * zapis (bez povezivanja). {@code hash} kolona je UNIQUE, pa se računa kao SHA-256 nad
 * sadržajem zapisa uz vremensku oznaku i nonce, čisto da bude jedinstven. Pravi linearni
 * hash-lanac (povezan {@code prevHash}), {@code verifyChain()} i anchoring dolaze u Fazi 11
 * i zameniće ovu implementaciju.
 */
@Service
public class AuditService {

    /** Stub vrednost dok se ne uvede pravi lanac (Faza 11). */
    static final String GENESIS = "GENESIS";

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Transactional
    public AuditLog record(String action, UUID actorId, String resource, String metadataJson) {
        AuditLog log = new AuditLog();
        log.setActorId(actorId);
        log.setAction(action);
        log.setResource(resource);
        log.setMetadata(metadataJson == null || metadataJson.isBlank() ? "{}" : metadataJson);
        log.setPrevHash(GENESIS);
        log.setHash(stubHash(action, actorId, resource, log.getMetadata()));
        return auditLogRepository.save(log);
    }

    /**
     * Privremeni jedinstven heš zapisa (Faza 3). Sadrži vremensku oznaku i nonce kako bi
     * {@code hash} (UNIQUE) bio jedinstven čak i za identičnu akciju. Faza 11 ovo menja
     * deterministicnim {@code SHA-256(canonical(payload) || prevHash)}.
     */
    private static String stubHash(String action, UUID actorId, String resource, String metadata) {
        String payload = String.join("|",
                String.valueOf(action),
                String.valueOf(actorId),
                String.valueOf(resource),
                metadata,
                OffsetDateTime.now().toString(),
                UUID.randomUUID().toString());
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 nije dostupan u JVM-u", e);
        }
    }
}
