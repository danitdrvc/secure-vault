package com.securevault.honeypot.repository;

import com.securevault.honeypot.domain.Honeytoken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface HoneytokenRepository extends JpaRepository<Honeytoken, UUID> {
}
