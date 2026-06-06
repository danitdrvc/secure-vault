package com.securevault.vault.repository;

import com.securevault.vault.domain.Secret;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface SecretRepository extends JpaRepository<Secret, UUID> {

    List<Secret> findByOwnerId(UUID ownerId);

    /** Regularni vault API izlistava samo prave tajne (honeytoken = false). */
    List<Secret> findByOwnerIdAndHoneytokenFalse(UUID ownerId);
}
