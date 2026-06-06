package com.securevault.auth.oidc;

/**
 * Razmena authorization code-a za verifikovani OIDC identitet (Faza 5).
 *
 * <p>Apstrakcija nad provajderom: produkciona implementacija ({@link HttpOidcAuthenticator})
 * razmenjuje code na token endpointu i verifikuje potpis id_token-a protiv JWKS-a; testovi
 * ubacuju lažni stub (bez živog provajdera). U oba slučaja rezultat je samo {@link OidcIdentity}
 * — nikad kripto materijal vault-a.
 */
public interface OidcAuthenticator {

    /**
     * Razmeni {@code code} za id_token, verifikuj ga (potpis, issuer, audience, istek) i
     * potvrdi da {@code nonce} u tokenu odgovara {@code expectedNonce}.
     *
     * @throws com.securevault.common.error.UnauthorizedException ako razmena/verifikacija ne uspe
     */
    OidcIdentity authenticate(String code, String expectedNonce);
}
