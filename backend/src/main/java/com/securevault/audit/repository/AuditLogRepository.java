package com.securevault.audit.repository;

import com.securevault.audit.domain.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    /** Vrh hash-lanca (poslednji upisani zapis) — koristi se za prevHash narednog. */
    Optional<AuditLog> findTopByOrderBySeqDesc();

    List<AuditLog> findByActorIdOrderBySeqAsc(UUID actorId);

    /** Ceo lanac u redosledu nastanka — za {@code verifyChain()}. */
    List<AuditLog> findAllByOrderBySeqAsc();

    /**
     * Serijalizuje upis u hash-lanac preko Postgres transakcione savetodavne brave
     * ({@code pg_advisory_xact_lock}). Brava se drži do COMMIT-a tekuće transakcije, pa dva
     * konkurentna {@code append}-a ne mogu pročitati isti vrh i „račvati" lanac (oba povezana
     * na isti {@code prevHash}). Upit se evaluira u podupitu da bi se funkcija sigurno izvršila.
     */
    @Query(value = "SELECT 1 FROM (SELECT pg_advisory_xact_lock(:key)) AS _chain_lock",
            nativeQuery = true)
    Integer acquireChainLock(@Param("key") long key);
}
