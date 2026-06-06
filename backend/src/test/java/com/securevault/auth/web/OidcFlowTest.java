package com.securevault.auth.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.auth.oidc.OidcAuthenticator;
import com.securevault.auth.oidc.OidcIdentity;
import com.securevault.user.domain.User;
import com.securevault.user.repository.UserRepository;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.securevault.auth.web.AuthCookieFactory.OIDC_STATE_COOKIE;
import static com.securevault.auth.web.AuthCookieFactory.REFRESH_COOKIE;
import static com.securevault.security.JwtCookieAuthenticationFilter.ACCESS_COOKIE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Acceptance (Faza 5): OIDC prijava. Pun stack nad embedded PostgreSQL-om, kroz MockMvc.
 *
 * <p>{@link OidcAuthenticator} je zamenjen stubom (bez živog provajdera): subject se izvodi iz
 * {@code code} parametra, pa svaki test bira da li je nalog povezan. Verifikuje se:
 * uspešan callback postavlja iste sesijske kolačiće kao Faza 4 ALI ne vraća vault materijal
 * (vault ostaje zaključan dok se ne unese master lozinka), i nepovezan/nevažeći callback ne
 * pravi sesiju.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@AutoConfigureEmbeddedDatabase(provider = AutoConfigureEmbeddedDatabase.DatabaseProvider.ZONKY)
@TestPropertySource(properties = {
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.flyway.enabled=true",
        "spring.flyway.locations=classpath:db/migration",
        "app.auth.cookie-secure=true",
        "app.oidc.enabled=true",
        "app.oidc.issuer=https://idp.test/",
        "app.oidc.client-id=secure-vault-test",
        "app.oidc.client-secret=test-secret",
        "app.oidc.authorization-uri=https://idp.test/authorize",
        "app.oidc.token-uri=https://idp.test/token",
        "app.oidc.jwks-uri=https://idp.test/jwks",
        "app.oidc.redirect-uri=http://localhost:8080/api/auth/oidc/callback",
        "app.oidc.post-login-redirect-uri=http://localhost:5173/login?oidc=success",
        "app.oidc.post-login-error-uri=http://localhost:5173/login?oidc=error"
})
class OidcFlowTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getEncoder();

    /**
     * Stub provajdera: subject = "sub:" + code, email = code + "@idp.test" (verifikovan), pa test
     * kontroliše i mapiranje po subject-u i prvo-login povezivanje po email-u (oba per-code
     * jedinstvena → bez ukrštanja između testova).
     */
    @TestConfiguration
    static class StubOidcConfig {
        @Bean
        @Primary
        OidcAuthenticator stubOidcAuthenticator() {
            return (code, expectedNonce) -> new OidcIdentity("sub:" + code, code + "@idp.test", true);
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Test
    void startPreusmeravaNaProvajderaIPostavljaStateKolacic() throws Exception {
        MvcResult result = mockMvc.perform(get("/auth/oidc/start"))
                .andExpect(status().isFound())
                .andReturn();

        String location = result.getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(location).startsWith("https://idp.test/authorize");
        assertThat(location).contains("client_id=secure-vault-test");
        assertThat(location).contains("response_type=code");
        assertThat(location).contains("state=");
        assertThat(location).contains("nonce=");

        Cookie state = result.getResponse().getCookie(OIDC_STATE_COOKIE);
        assertThat(state).isNotNull();
        assertThat(state.getValue()).isNotBlank();
        // State kolačić mora biti SameSite=Lax (da preživi cross-site redirect sa provajdera).
        String header = result.getResponse().getHeaders(HttpHeaders.SET_COOKIE).stream()
                .filter(h -> h.startsWith(OIDC_STATE_COOKIE + "=")).findFirst().orElseThrow();
        assertThat(header).contains("HttpOnly").contains("SameSite=Lax");
    }

    @Test
    void uspesanCallbackPostavljaSesijuAliNeVracaVaultMaterijal() throws Exception {
        String code = "good-" + UUID.randomUUID();
        String username = uniq("oidc");
        linkUser(username, "sub:" + code);

        StartData start = doStart();

        MvcResult callback = mockMvc.perform(get("/auth/oidc/callback")
                        .param("code", code)
                        .param("state", start.state())
                        .cookie(start.stateCookie()))
                .andExpect(status().isFound())
                .andReturn();

        // Preusmerava na frontend success URL.
        assertThat(callback.getResponse().getHeader(HttpHeaders.LOCATION))
                .isEqualTo("http://localhost:5173/login?oidc=success");

        // Postavljeni su access + refresh sesijski kolačići (kao Faza 4), ispravnih flegova.
        Cookie access = callback.getResponse().getCookie(ACCESS_COOKIE);
        Cookie refresh = callback.getResponse().getCookie(REFRESH_COOKIE);
        assertThat(access).isNotNull();
        assertThat(refresh).isNotNull();
        List<String> setCookies = callback.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        for (String name : List.of(ACCESS_COOKIE, REFRESH_COOKIE)) {
            String header = setCookies.stream().filter(h -> h.startsWith(name + "=")).findFirst().orElseThrow();
            assertThat(header).contains("HttpOnly").contains("Secure").contains("SameSite=Strict");
        }

        // KRITIČNO (zero-knowledge): odgovor ne sme da nosi vault materijal — vault je zaključan.
        String body = callback.getResponse().getContentAsString();
        assertThat(body).doesNotContain("encUsk").doesNotContain("encPrivateKey");

        // Sesija je validna: /auth/me radi sa access kolačićem.
        mockMvc.perform(get("/auth/me").cookie(access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username));

        // Vault se otključava TEK posebnim dohvatom šifrovanog materijala + master lozinkom na klijentu.
        mockMvc.perform(get("/auth/vault-material").cookie(access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.encUsk").exists())
                .andExpect(jsonPath("$.kdfSalt").exists());
    }

    @Test
    void prvaPrijavaPovezujeNalogPoVerifikovanomEmailu() throws Exception {
        // Nalog postoji ali NEMA oidc_subject; stub vrati verifikovan email == nalogov email.
        String code = "link-" + UUID.randomUUID();
        String email = code + "@idp.test";
        String username = registerWithEmail(uniq("emaillink"), email);

        StartData start = doStart();
        mockMvc.perform(get("/auth/oidc/callback")
                        .param("code", code)
                        .param("state", start.state())
                        .cookie(start.stateCookie()))
                .andExpect(status().isFound());

        // Nalog je trajno povezan sa OIDC subject-om i sesija je izdata.
        User linked = userRepository.findByUsername(username).orElseThrow();
        assertThat(linked.getOidcSubject()).isEqualTo("sub:" + code);
    }

    @Test
    void callbackZaNepovezanNalogNePraviSesiju() throws Exception {
        StartData start = doStart();

        MvcResult callback = mockMvc.perform(get("/auth/oidc/callback")
                        .param("code", "unlinked-" + UUID.randomUUID())
                        .param("state", start.state())
                        .cookie(start.stateCookie()))
                .andExpect(status().isFound())
                .andReturn();

        assertThat(callback.getResponse().getHeader(HttpHeaders.LOCATION))
                .isEqualTo("http://localhost:5173/login?oidc=error");
        assertThat(callback.getResponse().getCookie(ACCESS_COOKIE)).isNull();
        assertThat(callback.getResponse().getCookie(REFRESH_COOKIE)).isNull();
    }

    @Test
    void callbackSaNeispravnimStateNePraviSesiju() throws Exception {
        String code = "good-" + UUID.randomUUID();
        linkUser(uniq("oidc"), "sub:" + code);
        StartData start = doStart();

        // State iz query-ja se ne poklapa sa potpisanim u kolačiću → odbij (mogući CSRF).
        MvcResult callback = mockMvc.perform(get("/auth/oidc/callback")
                        .param("code", code)
                        .param("state", "podmetnut-state")
                        .cookie(start.stateCookie()))
                .andExpect(status().isFound())
                .andReturn();

        assertThat(callback.getResponse().getHeader(HttpHeaders.LOCATION))
                .isEqualTo("http://localhost:5173/login?oidc=error");
        assertThat(callback.getResponse().getCookie(ACCESS_COOKIE)).isNull();
    }

    // ----- pomoćne metode -----

    private record StartData(String state, Cookie stateCookie) {
    }

    /** Pokrene /start i izvuče state (iz Location) + potpisani state kolačić. */
    private StartData doStart() throws Exception {
        MvcResult result = mockMvc.perform(get("/auth/oidc/start"))
                .andExpect(status().isFound())
                .andReturn();
        String location = result.getResponse().getHeader(HttpHeaders.LOCATION);
        String state = location.replaceAll(".*[?&]state=([^&]+).*", "$1");
        return new StartData(state, result.getResponse().getCookie(OIDC_STATE_COOKIE));
    }

    /** Registruje korisnika (nasumični blobovi) i poveže ga sa datim OIDC subject-om. */
    private void linkUser(String username, String oidcSubject) throws Exception {
        registerWithEmail(username, username + "@securevault.local");
        User user = userRepository.findByUsername(username).orElseThrow();
        user.setOidcSubject(oidcSubject);
        userRepository.saveAndFlush(user);
    }

    /** Registruje korisnika sa zadatim email-om (bez OIDC povezivanja); vraća username. */
    private String registerWithEmail(String username, String email) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("username", username);
        payload.put("email", email);
        payload.put("kdfSalt", b64(16));
        payload.put("kdfIterations", 600_000);
        payload.put("authKey", b64(32));
        payload.put("encUsk", b64(60));
        payload.put("publicKey", b64(294));
        payload.put("encPrivateKey", b64(1245));

        mockMvc.perform(post("/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isCreated());
        return username;
    }

    private static String uniq(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    private static String b64(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return B64.encodeToString(b);
    }
}
