package com.securevault.audit.repository;

import com.securevault.audit.domain.AuditAnchor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuditAnchorRepository extends JpaRepository<AuditAnchor, UUID> {

    Optional<AuditAnchor> findTopByOrderByToSeqDesc();

    /** Poslednjih 20 sidara (najnovije prvo) — za admin pregled u UI-ju. */
    List<AuditAnchor> findTop20ByOrderByToSeqDesc();
}
