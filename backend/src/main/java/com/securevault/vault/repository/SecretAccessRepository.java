package com.securevault.vault.repository;

import com.securevault.vault.domain.SecretAccess;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SecretAccessRepository extends JpaRepository<SecretAccess, UUID> {

    List<SecretAccess> findByUserId(UUID userId);

    List<SecretAccess> findBySecretId(UUID secretId);

    Optional<SecretAccess> findBySecretIdAndUserId(UUID secretId, UUID userId);
}
