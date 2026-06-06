package com.securevault.auth.web;

import com.securevault.user.domain.User;

import java.util.Base64;

/**
 * Šifrovani vault materijal koji klijent dobija posle uspešnog logina da bi lokalno pozvao
 * {@code unlock(pw, ...)}. Sve je base64 šifrat — server ga ne može dešifrovati (zero-knowledge):
 * {@code kdfSalt}/{@code kdfIterations} (KDF parametri), {@code encUsk} (AES-GCM(KEK, USK)),
 * {@code publicKey} (SPKI), {@code encPrivateKey} (AES-GCM(USK, PKCS8)).
 */
public record VaultMaterial(String kdfSalt, int kdfIterations, String encUsk,
                            String publicKey, String encPrivateKey) {

    public static VaultMaterial from(User user) {
        Base64.Encoder b64 = Base64.getEncoder();
        return new VaultMaterial(
                b64.encodeToString(user.getKdfSalt()),
                user.getKdfIterations(),
                b64.encodeToString(user.getEncUsk()),
                b64.encodeToString(user.getPublicKey()),
                b64.encodeToString(user.getEncPrivateKey()));
    }
}
