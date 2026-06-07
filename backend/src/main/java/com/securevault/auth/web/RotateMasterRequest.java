package com.securevault.auth.web;

import com.securevault.common.validation.Base64Bytes;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

/**
 * Telo zahteva za promenu master lozinke ({@code POST /auth/rotate-master}, Faza 8).
 *
 * <p>Klijent OTKLJUČA stari vault (stara lozinka → KEK → USK), izvede NOVI KEK iz nove lozinke i
 * re-šifruje SAMO {@code encUsk} (i, sa svežim nonce-om, {@code encPrivateKey}); USK i privatni
 * ključ ostaju isti pa sve postojeće tajne i dalje rade. Server prima samo šifrovane artefakte +
 * dokaze identiteta:
 * <ul>
 *   <li>{@code currentAuthKey} — dokaz STARE lozinke (step-up re-auth); mora odgovarati {@code auth_hash}.</li>
 *   <li>{@code authKey} — NOVI dokaz; server čuva {@code bcrypt(authKey)}.</li>
 *   <li>{@code kdfSalt}/{@code kdfIterations} — novi KDF parametri (svež salt po promeni lozinke).</li>
 *   <li>{@code encUsk} — {@code AES-GCM(noviKEK, USK)} (USK nepromenjen).</li>
 *   <li>{@code encPrivateKey} — {@code AES-GCM(USK, PKCS8)} sa svežim nonce-om.</li>
 * </ul>
 * Master lozinka, KEK i USK (plaintext) NIKAD ne dolaze do servera (zero-knowledge).
 */
public record RotateMasterRequest(

        @NotBlank
        @Base64Bytes(min = 32, max = 32, message = "currentAuthKey mora biti tačno 32 bajta (base64)")
        String currentAuthKey,

        @NotBlank
        @Base64Bytes(min = 32, max = 32, message = "authKey mora biti tačno 32 bajta (base64)")
        String authKey,

        @NotBlank
        @Base64Bytes(min = 16, max = 16, message = "kdfSalt mora biti tačno 16 bajtova (base64)")
        String kdfSalt,

        @Min(value = 600_000, message = "kdfIterations mora biti najmanje 600000")
        @Max(value = 10_000_000, message = "kdfIterations je nerealno velik")
        int kdfIterations,

        @NotBlank
        @Base64Bytes(min = 60, max = 60, message = "encUsk mora biti tačno 60 bajtova (base64)")
        String encUsk,

        @NotBlank
        @Base64Bytes(min = 1230, max = 1300, message = "encPrivateKey nije šifrovan PKCS8 očekivane veličine")
        String encPrivateKey
) {
}
