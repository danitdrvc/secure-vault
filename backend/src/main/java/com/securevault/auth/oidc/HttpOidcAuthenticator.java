package com.securevault.auth.oidc;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.securevault.common.error.UnauthorizedException;
import com.securevault.config.OidcProperties;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;

/**
 * Produkciona OIDC razmena (Faza 5): authorization code → id_token na token endpointu, pa
 * verifikacija id_token-a protiv provajderovog JWKS-a (potpis, issuer, audience, istek, nonce)
 * preko Nimbus dekodera. Standardne biblioteke (Spring Security OAuth2 / Nimbus) — bez sopstvene
 * kripto/JWT logike.
 *
 * <p>JWKS dekoder se gradi lenjivo (na prvu upotrebu): dok je OIDC isključen ili nekonfigurisan,
 * bean postoji ali se nikad ne dotiče mreže.
 */
@Component
public class HttpOidcAuthenticator implements OidcAuthenticator {

    private final OidcProperties properties;
    private final RestClient http = RestClient.create();
    private volatile JwtDecoder decoder;

    public HttpOidcAuthenticator(OidcProperties properties) {
        this.properties = properties;
    }

    @Override
    public OidcIdentity authenticate(String code, String expectedNonce) {
        String idToken = exchangeCode(code);
        Jwt jwt = decode(idToken);

        String nonce = jwt.getClaimAsString("nonce");
        if (expectedNonce != null && !expectedNonce.equals(nonce)) {
            throw new UnauthorizedException("OIDC nonce ne odgovara.");
        }
        String subject = jwt.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new UnauthorizedException("OIDC token nema subject (sub).");
        }
        Boolean emailVerified = jwt.getClaimAsBoolean("email_verified");
        return new OidcIdentity(subject, jwt.getClaimAsString("email"), Boolean.TRUE.equals(emailVerified));
    }

    private String exchangeCode(String code) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", properties.getRedirectUri());
        form.add("client_id", properties.getClientId());
        form.add("client_secret", properties.getClientSecret());

        TokenResponse response;
        try {
            response = http.post()
                    .uri(properties.getTokenUri())
                    .contentType(APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(TokenResponse.class);
        } catch (RestClientException e) {
            throw new UnauthorizedException("OIDC razmena code-a nije uspela.");
        }
        if (response == null || response.idToken() == null || response.idToken().isBlank()) {
            throw new UnauthorizedException("OIDC token endpoint nije vratio id_token.");
        }
        return response.idToken();
    }

    private Jwt decode(String idToken) {
        try {
            return decoder().decode(idToken);
        } catch (JwtException e) {
            throw new UnauthorizedException("OIDC id_token nije validan.");
        }
    }

    private JwtDecoder decoder() {
        JwtDecoder local = decoder;
        if (local == null) {
            synchronized (this) {
                local = decoder;
                if (local == null) {
                    local = buildDecoder();
                    decoder = local;
                }
            }
        }
        return local;
    }

    private JwtDecoder buildDecoder() {
        NimbusJwtDecoder nimbus = NimbusJwtDecoder.withJwkSetUri(properties.getJwksUri()).build();
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        if (properties.getIssuer() != null && !properties.getIssuer().isBlank()) {
            validators.add(new JwtIssuerValidator(properties.getIssuer()));
        }
        validators.add(audienceValidator(properties.getClientId()));
        nimbus.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return nimbus;
    }

    /** Audience mora da sadrži naš client_id (token je izdat za nas, nije preusmeren). */
    private static OAuth2TokenValidator<Jwt> audienceValidator(String clientId) {
        OAuth2Error error = new OAuth2Error("invalid_token", "id_token audience ne sadrži client_id", null);
        return jwt -> jwt.getAudience() != null && jwt.getAudience().contains(clientId)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(error);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record TokenResponse(@JsonProperty("id_token") String idToken) {
    }
}
