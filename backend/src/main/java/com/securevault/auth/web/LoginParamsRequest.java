package com.securevault.auth.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Pre-login zahtev: klijent traži KDF parametre da bi iz master lozinke izveo {@code authKey}.
 * Salt i broj iteracija nisu tajna (server ih svejedno vraća pri loginu) — vraćaju se pre
 * dokaza identiteta da bi klijent uopšte mogao da izračuna {@code authKey}.
 */
public record LoginParamsRequest(
        @NotBlank
        @Size(max = 64)
        String username
) {
}
