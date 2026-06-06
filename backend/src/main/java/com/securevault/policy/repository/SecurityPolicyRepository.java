package com.securevault.policy.repository;

import com.securevault.policy.domain.SecurityPolicy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface SecurityPolicyRepository extends JpaRepository<SecurityPolicy, UUID> {

    /** Trenutno važeća politika (u svakom trenutku tačno jedna aktivna). */
    Optional<SecurityPolicy> findFirstByActiveTrue();

    long countByActiveTrue();
}
