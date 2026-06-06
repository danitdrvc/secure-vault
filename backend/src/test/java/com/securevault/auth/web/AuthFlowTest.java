package com.securevault.auth.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.policy.domain.SecurityPolicy;
import com.securevault.policy.repository.SecurityPolicyRepository;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
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

import static com.securevault.auth.web.AuthCookieFactory.REFRESH_COOKIE;
import static com.securevault.security.JwtCookieAuthenticationFilter.ACCESS_COOKIE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Acceptance (Faza 4): pun login tok (lozinka → TOTP → sesija), rotacija refresh tokena i
 * apsolutni cap sesije. Pun stack nad PRAVIM (embedded) PostgreSQL-om, kroz MockMvc.
 *
 * <p>{@code cookie-secure=true} je forsiran da bi se proverio {@code Secure} flag na kolačićima.
 * TOTP kodovi se računaju lokalno (isti algoritam kao server) — tajna se izvuče iz otpauth URI-ja
 * koji setup vraća (kao što bi je authenticator aplikacija učitala iz QR-a).
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@AutoConfigureEmbeddedDatabase(provider = AutoConfigureEmbeddedDatabase.DatabaseProvider.ZONKY)
@TestPropertySource(properties = {
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.flyway.enabled=true",
        "spring.flyway.locations=classpath:db/migration",
        "app.auth.cookie-secure=true"
})
class AuthFlowTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getEncoder();

    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SecurityPolicyRepository policyRepository;

    /** Pre svakog testa vrati politiku na poznate default vrednosti (testovi je menjaju). */
    @BeforeEach
    void resetPolicy() {
        SecurityPolicy policy = policyRepository.findFirstByActiveTrue().orElseThrow();
        policy.setAccessTokenTtlSec(300);
        policy.setRefreshTokenTtlSec(3600);
        policy.setSessionMaxTtlSec(1800);
        policyRepository.saveAndFlush(policy);
    }

    @Test
    void punTokSesijePostavljaDvaKolacicaSaIspravnimFlegovima() throws Exception {
        String username = uniq("dev");
        String authKey = register(username);

        String ticket = step1(username, authKey, false);
        String secret = setupAndEnableTotp(ticket);

        MvcResult step2 = mockMvc.perform(post("/auth/login/step2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("mfaTicket", ticket, "totpCode", currentCode(secret)))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.username").value(username))
                .andExpect(jsonPath("$.vault.encUsk").exists())
                .andExpect(jsonPath("$.vault.kdfSalt").exists())
                // Telo NE sme da sadrži sami token (tokeni su samo u kolačićima).
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andReturn();

        List<String> setCookies = step2.getResponse().getHeaders(HttpHeaders.SET_COOKIE);
        assertThat(setCookies).hasSize(2);
        String accessHeader = headerFor(setCookies, ACCESS_COOKIE);
        String refreshHeader = headerFor(setCookies, REFRESH_COOKIE);
        for (String header : List.of(accessHeader, refreshHeader)) {
            assertThat(header).contains("HttpOnly");
            assertThat(header).contains("Secure");
            assertThat(header).contains("SameSite=Strict");
        }

        // Sa važećim access kolačićem zaštićeni /auth/me vraća 200.
        Cookie access = step2.getResponse().getCookie(ACCESS_COOKIE);
        mockMvc.perform(get("/auth/me").cookie(access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username));

        // Bez kolačića → 401 (zaštićeno).
        mockMvc.perform(get("/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("UNAUTHORIZED"));
    }

    @Test
    void loginBezValidnogTotpVraca401() throws Exception {
        String username = uniq("nototp");
        String authKey = register(username);
        String ticket = step1(username, authKey, false);
        String secret = setupAndEnableTotp(ticket);

        // Pogrešan kod (daleko od svakog validnog prozora) → 401, bez kolačića.
        MvcResult result = mockMvc.perform(post("/auth/login/step2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("mfaTicket", ticket, "totpCode", wrongCode(secret)))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("UNAUTHORIZED"))
                .andReturn();
        assertThat(result.getResponse().getHeaders(HttpHeaders.SET_COOKIE)).isEmpty();
    }

    @Test
    void pogresnaLozinkaVraca401() throws Exception {
        String username = uniq("badpw");
        register(username);

        mockMvc.perform(post("/auth/login/step1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("username", username, "authKey", b64(32)))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rotacijaRefreshTokenaPonistavaStari() throws Exception {
        String username = uniq("rot");
        String authKey = register(username);
        String ticket = step1(username, authKey, false);
        String secret = setupAndEnableTotp(ticket);

        MvcResult login = step2(ticket, currentCode(secret));
        Cookie oldRefresh = login.getResponse().getCookie(REFRESH_COOKIE);
        assertThat(oldRefresh).isNotNull();

        // Prvi refresh prolazi i izdaje NOV refresh.
        MvcResult refreshed = mockMvc.perform(post("/auth/refresh").cookie(oldRefresh))
                .andExpect(status().isOk())
                .andReturn();
        Cookie newRefresh = refreshed.getResponse().getCookie(REFRESH_COOKIE);
        assertThat(newRefresh).isNotNull();
        assertThat(newRefresh.getValue()).isNotEqualTo(oldRefresh.getValue());

        // Ponovna upotreba STAROG refresh tokena → 401 (rotacija ga je poništila).
        mockMvc.perform(post("/auth/refresh").cookie(oldRefresh))
                .andExpect(status().isUnauthorized());

        // NOVI refresh i dalje radi.
        mockMvc.perform(post("/auth/refresh").cookie(newRefresh))
                .andExpect(status().isOk());
    }

    @Test
    void posleIstekaAccessTokenaMeVraca401PaRefreshIzdajeNov() throws Exception {
        // Kratak access TTL da token brzo istekne; refresh/sesija ostaju dugi.
        setPolicy(1, 3600, 1800);

        String username = uniq("exp");
        String authKey = register(username);
        String ticket = step1(username, authKey, false);
        String secret = setupAndEnableTotp(ticket);

        MvcResult login = step2(ticket, currentCode(secret));
        Cookie access = login.getResponse().getCookie(ACCESS_COOKIE);
        Cookie refresh = login.getResponse().getCookie(REFRESH_COOKIE);

        Thread.sleep(1_300); // pusti da access token (TTL 1s) istekne

        // Posle isteka access TTL-a zaštićeni endpoint vraća 401.
        mockMvc.perform(get("/auth/me").cookie(access)).andExpect(status().isUnauthorized());

        // Vrati normalan access TTL PRE refresh-a da novi token ima komforan vek (bez trke sa 1s).
        setPolicy(300, 3600, 1800);

        // Refresh (sesija/refresh još važe) izdaje NOV access koji ponovo otvara /auth/me.
        MvcResult refreshed = mockMvc.perform(post("/auth/refresh").cookie(refresh))
                .andExpect(status().isOk())
                .andReturn();
        Cookie newAccess = refreshed.getResponse().getCookie(ACCESS_COOKIE);
        mockMvc.perform(get("/auth/me").cookie(newAccess)).andExpect(status().isOk());
    }

    @Test
    void posleApsolutnogCapaSesijeRefreshVraca401() throws Exception {
        // Cap sesije = 1s, ali refresh TTL = 3600s: jedino cap obara refresh posle 1s.
        setPolicy(300, 3600, 1);

        String username = uniq("cap");
        String authKey = register(username);
        String ticket = step1(username, authKey, false);
        String secret = setupAndEnableTotp(ticket);

        MvcResult login = step2(ticket, currentCode(secret));
        Cookie refresh = login.getResponse().getCookie(REFRESH_COOKIE);

        Thread.sleep(1_300); // pređi apsolutni cap sesije

        mockMvc.perform(post("/auth/refresh").cookie(refresh))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginParamsVracaSaltIIteracije() throws Exception {
        String username = uniq("params");
        register(username);

        mockMvc.perform(post("/auth/login/params")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("username", username))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kdfIterations").value(600_000))
                .andExpect(jsonPath("$.kdfSalt").exists());
    }

    // ----- pomoćne metode -----

    /** Registruje korisnika sa nasumičnim kripto blobovima; vraća base64 authKey za login. */
    private String register(String username) throws Exception {
        String authKey = b64(32);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("username", username);
        payload.put("email", username + "@securevault.local");
        payload.put("kdfSalt", b64(16));
        payload.put("kdfIterations", 600_000);
        payload.put("authKey", authKey);
        payload.put("encUsk", b64(60));
        payload.put("publicKey", b64(294));
        payload.put("encPrivateKey", b64(1245));

        mockMvc.perform(post("/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(payload)))
                .andExpect(status().isCreated());
        return authKey;
    }

    private String step1(String username, String authKey, boolean expectTotpEnabled) throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/login/step1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("username", username, "authKey", authKey))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mfaRequired").value(true))
                .andExpect(jsonPath("$.totpEnabled").value(expectTotpEnabled))
                .andReturn();
        return field(result, "mfaTicket");
    }

    /** TOTP setup → izvuci tajnu iz otpauth URI-ja → verify (uključi totp) → vrati tajnu. */
    private String setupAndEnableTotp(String ticket) throws Exception {
        MvcResult setup = mockMvc.perform(post("/auth/totp/setup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("mfaTicket", ticket))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.qrDataUri").exists())
                .andReturn();
        String secret = secretFromUri(field(setup, "otpauthUri"));

        mockMvc.perform(post("/auth/totp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("mfaTicket", ticket, "totpCode", currentCode(secret)))))
                .andExpect(status().isNoContent());
        return secret;
    }

    private MvcResult step2(String ticket, String code) throws Exception {
        return mockMvc.perform(post("/auth/login/step2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("mfaTicket", ticket, "totpCode", code))))
                .andExpect(status().isOk())
                .andExpect(cookie().exists(ACCESS_COOKIE))
                .andExpect(cookie().exists(REFRESH_COOKIE))
                .andReturn();
    }

    private void setPolicy(int accessTtl, int refreshTtl, int sessionMaxTtl) {
        SecurityPolicy policy = policyRepository.findFirstByActiveTrue().orElseThrow();
        policy.setAccessTokenTtlSec(accessTtl);
        policy.setRefreshTokenTtlSec(refreshTtl);
        policy.setSessionMaxTtlSec(sessionMaxTtl);
        policyRepository.saveAndFlush(policy);
    }

    private String currentCode(String secret) {
        try {
            long counter = Math.floorDiv(timeProvider.getTime(), 30);
            return codeGenerator.generate(secret, counter);
        } catch (CodeGenerationException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Kod udaljen pola opsega od validnog — ne poklapa se ni sa jednim prozorom tolerancije. */
    private String wrongCode(String secret) {
        int valid = Integer.parseInt(currentCode(secret));
        return String.format("%06d", (valid + 500_000) % 1_000_000);
    }

    private static String secretFromUri(String otpauthUri) {
        return otpauthUri.replaceAll(".*[?&]secret=([^&]+).*", "$1");
    }

    private String field(MvcResult result, String name) throws Exception {
        JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
        return node.get(name).asText();
    }

    private static String headerFor(List<String> setCookies, String cookieName) {
        return setCookies.stream()
                .filter(h -> h.startsWith(cookieName + "="))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Nema Set-Cookie za " + cookieName));
    }

    private String json(Map<String, ?> body) throws Exception {
        return objectMapper.writeValueAsString(body);
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
