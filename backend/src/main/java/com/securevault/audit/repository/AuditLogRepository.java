package com.securevault.audit.repository;

import com.securevault.audit.domain.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    /** Vrh hash-lanca (poslednji upisani zapis) — koristi se za prevHash narednog. */
    Optional<AuditLog> findTopByOrderBySeqDesc();

    List<AuditLog> findByActorIdOrderBySeqAsc(UUID actorId);
}
