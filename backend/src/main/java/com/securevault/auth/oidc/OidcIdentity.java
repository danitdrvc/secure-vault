package com.securevault.auth.oidc;

/**
 * Verifikovani identitet iz OIDC id_token-a (Faza 5). Sadrži samo ne-tajne metapodatke:
 * {@code subject} (stabilni {@code sub} claim provajdera, mapira se na {@code users.oidc_subject}),
 * {@code email} i {@code emailVerified} (da li je provajder potvrdio vlasništvo nad email-om —
 * uslov za prvo-login povezivanje sa postojećim nalogom). NIKAD ne nosi kripto materijal — OIDC
 * ne otključava vault.
 */
public record OidcIdentity(String subject, String email, boolean emailVerified) {
}
