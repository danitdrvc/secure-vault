package com.securevault.user.web;

import com.securevault.user.domain.User;

import java.util.Base64;
import java.util.UUID;

/**
 * Javni ključ korisnika ({@code GET /users/{id}/public-key}). Koristi ga onaj ko deli tajnu
 * (Faza 7) da uvije {@code secretKey} ka primaocu (RSA-OAEP). Javni ključ je po prirodi
 * javan — server ga skladišti i prosleđuje kao SPKI base64; nijedan privatni materijal se
 * ovde ne otkriva (zero-knowledge ostaje očuvan).
 */
public record PublicKeyResponse(UUID userId, String publicKey) {

    public static PublicKeyResponse from(User user) {
        return new PublicKeyResponse(
                user.getId(),
                Base64.getEncoder().encodeToString(user.getPublicKey()));
    }
}
