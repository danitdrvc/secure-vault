package com.securevault.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Konfiguracija OIDC prijave vezana na {@code app.oidc.*} (vidi application.yml), Faza 5.
 *
 * <p>OIDC daje SAMO sesiju (autentikaciju eksternim nalogom) — NIKAD vault ključ. Master
 * lozinka ostaje obavezna za otključavanje vault-a, pa zero-knowledge nije narušen. Sve
 * vrednosti dolaze iz env-a; podrazumevano je {@code enabled=false} (endpointi vraćaju 404
 * dok admin ne konfiguriše provajdera).
 */
@ConfigurationProperties(prefix = "app.oidc")
public class OidcProperties {

    /** Da li je OIDC prijava omogućena. Dok je false, {@code /auth/oidc/**} vraća 404. */
    private boolean enabled = false;

    /** {@code iss} provajdera — validira se na id_token-u. */
    private String issuer;

    /** Identifikator klijenta (aplikacije) kod provajdera. */
    private String clientId;

    /** Tajna klijenta (poverljiv klijent) za razmenu authorization code-a. */
    private String clientSecret;

    /** Authorization endpoint provajdera (gde se preusmerava browser na /start). */
    private String authorizationUri;

    /** Token endpoint provajdera (razmena code-a za id_token). */
    private String tokenUri;

    /** JWKS endpoint provajdera (javni ključevi za verifikaciju potpisa id_token-a). */
    private String jwksUri;

    /** Callback URL (kroz gateway) na koji provajder vraća browser sa authorization code-om. */
    private String redirectUri;

    /** OAuth2 scope-ovi (razmak-razdvojeni). {@code openid} je obavezan. */
    private String scopes = "openid email profile";

    /** Frontend URL na koji se browser vraća posle uspešne OIDC prijave (sesija postavljena). */
    private String postLoginRedirectUri;

    /** Frontend URL na koji se browser vraća kad OIDC prijava ne uspe. */
    private String postLoginErrorUri;

    /** Trajanje privremenog state/nonce kolačića tokom OIDC redirect toka (sekunde). */
    private int stateTtlSec = 300;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getAuthorizationUri() {
        return authorizationUri;
    }

    public void setAuthorizationUri(String authorizationUri) {
        this.authorizationUri = authorizationUri;
    }

    public String getTokenUri() {
        return tokenUri;
    }

    public void setTokenUri(String tokenUri) {
        this.tokenUri = tokenUri;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public String getPostLoginRedirectUri() {
        return postLoginRedirectUri;
    }

    public void setPostLoginRedirectUri(String postLoginRedirectUri) {
        this.postLoginRedirectUri = postLoginRedirectUri;
    }

    public String getPostLoginErrorUri() {
        return postLoginErrorUri;
    }

    public void setPostLoginErrorUri(String postLoginErrorUri) {
        this.postLoginErrorUri = postLoginErrorUri;
    }

    public int getStateTtlSec() {
        return stateTtlSec;
    }

    public void setStateTtlSec(int stateTtlSec) {
        this.stateTtlSec = stateTtlSec;
    }
}
