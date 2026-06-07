package com.securevault.vault.repository;

import com.securevault.vault.domain.Secret;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface SecretRepository extends JpaRepository<Secret, UUID> {

    List<Secret> findByOwnerId(UUID ownerId);

    /** Regularni vault API izlistava samo prave tajne (honeytoken = false). */
    List<Secret> findByOwnerIdAndHoneytokenFalse(UUID ownerId);

    /**
     * Sve tajne kojima korisnik ima pristup (preko {@code secret_access}), uz izostavljanje
     * honeytokena. Theta-join nad {@code SecretAccess} (bez mapirane relacije): jedinstven
     * par {@code (secret_id, user_id)} garantuje da nema duplikata. Pokriva i vlasnika
     * (koji pri kreiranju dobija svoj {@code secret_access} red) i — od Faze 7 — sve primaoce.
     */
    @Query("select s from Secret s, SecretAccess a "
            + "where a.secretId = s.id and a.userId = :userId and s.honeytoken = false "
            + "order by s.createdAt")
    List<Secret> findAccessibleNonHoneytoken(@Param("userId") UUID userId);
}
