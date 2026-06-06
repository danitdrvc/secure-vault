package com.securevault.auth.service;

import com.securevault.config.AuthProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Server-side simetrična enkripcija (AES-256-GCM) za podatke koji su IZVAN zero-knowledge
 * domena — konkretno TOTP tajne ({@code users.totp_secret_enc}). To je auth materijal koji
 * server mora moći da pročita da bi verifikovao kod; NIJE sadržaj vault-a.
 *
 * <p>Ključ se izvodi kao {@code SHA-256(SERVER_KMS_KEY)} → tačno 32 bajta, pa konfiguracija
 * može biti proizvoljan string. Format šifrata: {@code nonce(12) || ciphertext || tag(16)}.
 */
@Component
public class ServerSecretCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    public ServerSecretCipher(AuthProperties properties) {
        this.key = deriveKey(properties.getServerKmsKey());
    }

    private static SecretKeySpec deriveKey(String material) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(material.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(digest, "AES");
        } catch (Exception e) {
            throw new IllegalStateException("Ne mogu da izvedem server KMS ključ", e);
        }
    }

    /** Šifruje plaintext; vraća {@code nonce || ciphertext+tag}. */
    public byte[] encrypt(String plaintext) {
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] out = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, out, 0, nonce.length);
            System.arraycopy(ciphertext, 0, out, nonce.length, ciphertext.length);
            return out;
        } catch (Exception e) {
            throw new IllegalStateException("Šifrovanje TOTP tajne nije uspelo", e);
        }
    }

    /** Dešifruje {@code nonce || ciphertext+tag} nazad u plaintext. */
    public String decrypt(byte[] blob) {
        try {
            byte[] nonce = Arrays.copyOfRange(blob, 0, NONCE_BYTES);
            byte[] ciphertext = Arrays.copyOfRange(blob, NONCE_BYTES, blob.length);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Dešifrovanje TOTP tajne nije uspelo", e);
        }
    }
}
