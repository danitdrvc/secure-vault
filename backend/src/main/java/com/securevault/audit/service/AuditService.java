package com.securevault.audit.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.securevault.audit.domain.AuditLog;
import com.securevault.audit.repository.AuditLogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * Append-only revizija sa nepromenljivim hash-lancem (Faza 11).
 *
 * <p>Svaki zapis nosi {@code hash = SHA-256(canonicalJSON(payload) || prevHash)}, gde je
 * {@code prevHash} heš prethodnog zapisa (prvi koristi {@link #GENESIS}). Tiha izmena bilo kog
 * polja menja njegov heš → prekida vezu sa sledećim zapisom, pa je {@link #verify()} detektuje.
 *
 * <h3>Determinizam heša</h3>
 * <ul>
 *   <li><b>Kanonski JSON:</b> {@code metadata} (jsonb) Postgres normalizuje (razmaci, redosled
 *       ključeva), pa se i pri upisu i pri proveri svodi na kompaktan oblik sa sortiranim
 *       ključevima — round-trip kroz bazu ne menja heš.
 *   <li><b>Vreme:</b> {@code createdAt} se postavlja eksplicitno (UTC, skraćeno na mikrosekunde =
 *       preciznost {@code timestamptz}-a) i u heš ulazi kao {@code Instant} (uvek UTC), pa
 *       reprezentacija vremenske zone pri čitanju ne utiče na rezultat.
 *   <li><b>{@code seq}:</b> NIJE deo heša (dodeljuje ga baza tek pri upisu); redosled lanca
 *       čuva povezanost {@code prevHash → hash}, a {@code seq} služi samo za prolaz kroz lanac.
 * </ul>
 *
 * <h3>Serijalizacija upisa</h3>
 * {@link #append} uzima transakcionu savetodavnu bravu ({@code pg_advisory_xact_lock}) pre čitanja
 * vrha lanca; brava se drži do COMMIT-a, pa konkurentni upisi ne mogu račvati lanac.
 */
@Service
public class AuditService {

    /** Sidro lanca: {@code prevHash} prvog (genesis) zapisa. */
    static final String GENESIS = "GENESIS";

    /** Fiksni ključ transakcione savetodavne brave kojom se serijalizuju upisi u lanac. */
    private static final long CHAIN_LOCK_KEY = 0x5EC0_AD17_C8A1_4E60L;

    /** Izolovan mapper samo za (de)serijalizaciju kanonskog payload-a — nezavisan od web konfiguracije. */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    /**
     * Dopisuje zapis na kraj hash-lanca (append-only). Učita {@code prevHash} (vrh lanca),
     * izračuna {@code hash = SHA-256(canonicalJSON(payload) || prevHash)} i upiše novi zapis.
     *
     * @param action      tip akcije (npr. {@code LOGIN_SUCCESS})
     * @param actorId     korisnik koji je izazvao akciju, ili {@code null}
     * @param resource    pogođeni resurs (npr. {@code secrets/<id>}), ili {@code null}
     * @param metadataJson dodatni kontekst kao JSON; {@code null}/prazno → {@code "{}"}
     * @return upisani zapis
     */
    @Transactional
    public AuditLog append(String action, UUID actorId, String resource, String metadataJson) {
        // Serijalizuj upise: brava se drži do commit-a → nema račvanja lanca pri konkurentnosti.
        auditLogRepository.acquireChainLock(CHAIN_LOCK_KEY);

        String prevHash = auditLogRepository.findTopByOrderBySeqDesc()
                .map(AuditLog::getHash)
                .orElse(GENESIS);

        String canonicalMetadata = canonicalJson(metadataJson);
        OffsetDateTime createdAt = OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS);
        String hash = computeHash(action, actorId, resource, canonicalMetadata, createdAt, prevHash);

        AuditLog log = new AuditLog();
        log.setActorId(actorId);
        log.setAction(action);
        log.setResource(resource);
        log.setMetadata(canonicalMetadata);
        log.setCreatedAt(createdAt);
        log.setPrevHash(prevHash);
        log.setHash(hash);
        return auditLogRepository.save(log);
    }

    /**
     * Prolazi ceo lanac u redosledu {@code seq} i potvrđuje (1) povezanost
     * ({@code prevHash} == heš prethodnog) i (2) da svaki zapis ima ispravno preračunat heš.
     * Vraća prvi nekonzistentan {@code seq} ako lanac nije netaknut.
     */
    @Transactional(readOnly = true)
    public AuditVerificationResult verify() {
        List<AuditLog> chain = auditLogRepository.findAllByOrderBySeqAsc();
        String expectedPrev = GENESIS;
        long checked = 0;
        for (AuditLog log : chain) {
            checked++;
            boolean linkOk = expectedPrev.equals(log.getPrevHash());
            String recomputed = computeHash(log.getAction(), log.getActorId(), log.getResource(),
                    canonicalJson(log.getMetadata()), log.getCreatedAt(), log.getPrevHash());
            boolean hashOk = recomputed.equals(log.getHash());
            if (!linkOk || !hashOk) {
                return AuditVerificationResult.broken(checked, log.getSeq());
            }
            expectedPrev = log.getHash();
        }
        return AuditVerificationResult.ok(checked);
    }

    /** Pogodno za testove/kratke provere: {@code true} ako je ceo lanac netaknut. */
    @Transactional(readOnly = true)
    public boolean verifyChain() {
        return verify().valid();
    }

    /** Poslednjih 100 zapisa (najnoviji prvi) — za admin pregled u UI-ju. */
    @Transactional(readOnly = true)
    public List<AuditLog> recent() {
        return auditLogRepository.findTop100ByOrderBySeqDesc();
    }

    /**
     * {@code SHA-256(canonicalJSON(payload) || prevHash)}. Payload su sadržajna polja zapisa
     * (bez {@code seq}); {@code prevHash} se nadovezuje na kraj, po formuli iz plana.
     */
    private static String computeHash(String action, UUID actorId, String resource,
                                      String canonicalMetadata, OffsetDateTime createdAt,
                                      String prevHash) {
        ObjectNode payload = MAPPER.createObjectNode();
        // Ključevi se ubacuju abecednim redom → deterministična serijalizacija (bez dodatnih feature-a).
        payload.put("action", action);
        if (actorId == null) {
            payload.putNull("actorId");
        } else {
            payload.put("actorId", actorId.toString());
        }
        payload.put("createdAt", createdAt.toInstant().truncatedTo(ChronoUnit.MICROS).toString());
        payload.set("metadata", parse(canonicalMetadata));
        if (resource == null) {
            payload.putNull("resource");
        } else {
            payload.put("resource", resource);
        }

        String canonical;
        try {
            canonical = MAPPER.writeValueAsString(payload);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Serijalizacija audit payload-a nije uspela", e);
        }
        return sha256Hex(canonical + prevHash);
    }

    /** Kompaktan JSON sa rekurzivno sortiranim ključevima — stabilan bez obzira na jsonb normalizaciju. */
    private static String canonicalJson(String raw) {
        try {
            return MAPPER.writeValueAsString(sortNode(parse(raw)));
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Kanonikalizacija metadata nije uspela", e);
        }
    }

    private static JsonNode parse(String raw) {
        String json = (raw == null || raw.isBlank()) ? "{}" : raw;
        try {
            return MAPPER.readTree(json);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Audit metadata nije validan JSON", e);
        }
    }

    /** Rekurzivno sortira ključeve objekata (nizovi zadržavaju redosled) za stabilan kanonski oblik. */
    private static JsonNode sortNode(JsonNode node) {
        if (node.isObject()) {
            ObjectNode sorted = MAPPER.createObjectNode();
            List<String> names = new ArrayList<>();
            node.fieldNames().forEachRemaining(names::add);
            Collections.sort(names);
            for (String name : names) {
                sorted.set(name, sortNode(node.get(name)));
            }
            return sorted;
        }
        if (node.isArray()) {
            ArrayNode arr = MAPPER.createArrayNode();
            for (JsonNode el : node) {
                arr.add(sortNode(el));
            }
            return arr;
        }
        return node;
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 nije dostupan u JVM-u", e);
        }
    }
}
