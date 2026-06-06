package com.securevault.honeypot.repository;

import com.securevault.honeypot.domain.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {

    List<SecurityEvent> findByTypeOrderByCreatedAtDesc(String type);

    List<SecurityEvent> findByUserIdOrderByCreatedAtDesc(UUID userId);
}
