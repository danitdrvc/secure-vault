package com.securevault.honeypot.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.honeypot.domain.Honeytoken;
import com.securevault.honeypot.repository.HoneytokenRepository;
import com.securevault.honeypot.repository.SecurityEventRepository;
import com.securevault.policy.domain.SecurityPolicy;
import com.securevault.policy.repository.SecurityPolicyRepository;
import com.securevault.user.domain.User;
import com.securevault.user.domain.UserStatus;
import com.securevault.user.repository.UserRepository;
import com.securevault.vault.domain.Secret;
import com.securevault.vault.domain.SecretAccess;
import com.securevault.vault.repository.SecretAccessRepository;
import com.securevault.vault.repository.SecretRepository;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static com.securevault.security.JwtCookieAuthenticationFilter.ACCESS_COOKIE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Acceptance (Faza 10): Honeypot i Honeytokens.
 *
 * <p>Pokriva:
 * <ul>
 *   <li>Direktan pristup honeytoken tajni → 404 + korisnik FROZEN + security_event HONEYPOT_HIT.
 *   <li>Regularni listing nikad ne otkriva honeytokene.
 *   <li>Ranjivi endpoint: 404 kada je {@code honeypot_endpoint=false}.
 *   <li>Ranjivi endpoint + normalna pretraga bez pogotka → korisnik ostaje ACTIVE.
 *   <li>Ranjivi endpoint + SQLi payload koji pogodi honeytoken → FROZEN + security_event.
 *   <li>Zamrznut nalog ne može da se ponovo uloguje (403 u step1).
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@AutoConfigureEmbeddedDatabase(provider = AutoConfigureEmbeddedDatabase.DatabaseProvider.ZONKY)
@TestPropertySource(properties = {
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.flyway.enabled=true",
        "spring.flyway.locations=classpath:db/migration"
})
class HoneypotEndpointTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getEncoder();

    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired UserRepository userRepository;
    @Autowired SecurityPolicyRepository policyRepository;
    @Autowired SecurityEventRepository securityEventRepository;
    @Autowired HoneytokenRepository honeytokenRepository;
    @Autowired SecretRepository secretRepository;
    @Autowired SecretAccessRepository secretAccessRepository;

    /** Uključuje honeypot_endpoint pre svakog testa koji to treba (testovi koji ga ne trebaju ga onemogućuju sami). */
    @BeforeEach
    void enableHoneypotEndpoint() {
        SecurityPolicy policy = policyRepository.findFirstByActiveTrue().orElseThrow();
        policy.setHoneypotEndpoint(true);
        policyRepository.saveAndFlush(policy);
    }

    @AfterEach
    void resetHoneypotEndpoint() {
        SecurityPolicy policy = policyRepository.findFirstByActiveTrue().orElseThrow();
        policy.setHoneypotEndpoint(false);
        policyRepository.saveAndFlush(policy);
    }

    // ----- 1. Direktan pristup honeytoken tajni kroz regularni API -----

    @Test
    void direktanPristupHoneytokenTajniZamrzavaKorisnika() throws Exception {
        String username = uniq("hon-direct");
        Cookie access = login(username);
        User user = userRepository.findByUsername(username).orElseThrow();

        UUID honeySecretId = seedHoneytokenSecret(user.getId());
        long eventsBefore = securityEventRepository.count();

        // Pokušaj direktnog GET /vault/secrets/:id → uvek 404 (honeytoken je nevidljiv).
        mockMvc.perform(get("/vault/secrets/" + honeySecretId).cookie(access))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));

        // Nalog mora biti FROZEN.
        User refreshed = userRepository.findById(user.getId()).orElseThrow();
        assertThat(refreshed.getStatus()).isEqualTo(UserStatus.FROZEN);

        // security_event HONEYPOT_HIT mora biti kreiran.
        assertThat(securityEventRepository.count()).isGreaterThan(eventsBefore);
        var events = securityEventRepository.findByTypeOrderByCreatedAtDesc("HONEYPOT_HIT");
        assertThat(events).isNotEmpty();
        assertThat(events.get(0).getUserId()).isEqualTo(user.getId());
    }

    @Test
    void listingNikadNeOtkrivаHoneytokene() throws Exception {
        String username = uniq("hon-list");
        Cookie access = login(username);
        User user = userRepository.findByUsername(username).orElseThrow();

        // Jedna prava tajna + jedan honeytoken.
        createSecret(access, "prava-tajna");
        seedHoneytokenSecret(user.getId());

        MvcResult list = mockMvc.perform(get("/vault/secrets").cookie(access))
                .andExpect(status().isOk())
                .andReturn();

        String body = list.getResponse().getContentAsString();
        // Prava tajna prisutna.
        assertThat(body).contains("prava-tajna");
        // Honeytoken NIJE u listi (filtrira se na DB nivou).
        assertThat(body).doesNotContain("honeytoken");

        // Korisnik ostaje ACTIVE (listing ne okida honeypot).
        User refreshed = userRepository.findById(user.getId()).orElseThrow();
        assertThat(refreshed.getStatus()).isEqualTo(UserStatus.ACTIVE);
    }

    // ----- 2. Ranjivi endpoint (honeypot_endpoint flag) -----

    @Test
    void ranjivEndpointVraca404KadaJeIsključen() throws Exception {
        // Isključi endpoint.
        SecurityPolicy policy = policyRepository.findFirstByActiveTrue().orElseThrow();
        policy.setHoneypotEndpoint(false);
        policyRepository.saveAndFlush(policy);

        Cookie access = login(uniq("hon-off"));

        mockMvc.perform(get("/honeypot/search").param("label", "test").cookie(access))
                .andExpect(status().isNotFound());
    }

    @Test
    void normalnaPretragazBezPogotkaNeZamrzavaKorisnika() throws Exception {
        String username = uniq("hon-nomatch");
        Cookie access = login(username);
        User user = userRepository.findByUsername(username).orElseThrow();

        // Honeytoken sa poznatom labelom.
        insertHoneytoken("secret-aws-key-12345");

        // Pretraga po labeli koja ne postoji → prazna lista.
        mockMvc.perform(get("/honeypot/search").param("label", "no-match-at-all").cookie(access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$").isEmpty());

        // Korisnik ostaje ACTIVE.
        User refreshed = userRepository.findById(user.getId()).orElseThrow();
        assertThat(refreshed.getStatus()).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void sqliPayloadKojiPogodjiHoneytokenZamrzavaKorisnika() throws Exception {
        String username = uniq("hon-sqli");
        Cookie access = login(username);
        User user = userRepository.findByUsername(username).orElseThrow();

        insertHoneytoken("production-db-password");

        long eventsBefore = securityEventRepository.count();

        // SQLi payload: ' OR '1'='1' -- → vraća sve honeytokene.
        mockMvc.perform(get("/honeypot/search")
                        .param("label", "' OR '1'='1' --")
                        .cookie(access))
                .andExpect(status().isOk());

        // Nalog mora biti FROZEN.
        User refreshed = userRepository.findById(user.getId()).orElseThrow();
        assertThat(refreshed.getStatus()).isEqualTo(UserStatus.FROZEN);

        // security_event HONEYPOT_HIT mora biti kreiran.
        assertThat(securityEventRepository.count()).isGreaterThan(eventsBefore);
        var events = securityEventRepository.findByTypeOrderByCreatedAtDesc("HONEYPOT_HIT");
        assertThat(events).isNotEmpty();
        assertThat(events.get(0).getUserId()).isEqualTo(user.getId());
    }

    // ----- 3. Zamrznut nalog ne može da se uloguje -----

    @Test
    void zamrznutNalogNeMozeDaSeUloguje() throws Exception {
        String username = uniq("hon-frozen");

        // Registruj ručno da dobijemo authKey (potreban za ponovni login test).
        String authKey = register(username);
        String ticket = step1(username, authKey);
        String totpSecret = setupAndEnableTotp(ticket);
        MvcResult step2Result = mockMvc.perform(post("/auth/login/step2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("mfaTicket", ticket, "totpCode", currentCode(totpSecret)))))
                .andExpect(status().isOk())
                .andReturn();
        Cookie access = step2Result.getResponse().getCookie(ACCESS_COOKIE);
        assertThat(access).isNotNull();

        User user = userRepository.findByUsername(username).orElseThrow();

        // Zamrzni nalog pristupanjem honeytokenu.
        UUID honeySecretId = seedHoneytokenSecret(user.getId());
        mockMvc.perform(get("/vault/secrets/" + honeySecretId).cookie(access))
                .andExpect(status().isNotFound());

        // Provjeri da je FROZEN.
        User refreshed = userRepository.findById(user.getId()).orElseThrow();
        assertThat(refreshed.getStatus()).isEqualTo(UserStatus.FROZEN);

        // Pokušaj ponovnog logina sa tačnim authKey → 403 (nalog FROZEN).
        mockMvc.perform(post("/auth/login/step1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("username", username, "authKey", authKey))))
                .andExpect(status().isForbidden());
    }

    // ----- Pomoćne metode -----

    private String createSecret(Cookie access, String name) throws Exception {
        MvcResult result = mockMvc.perform(post("/vault/secrets")
                        .cookie(access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("name", name, "encryptedBlob", b64(48), "wrappedSecretKey", b64(256)))))
                .andExpect(status().isCreated())
                .andReturn();
        return field(result, "id");
    }

    /** Ubacuje honeytoken tajnu u secrets tabelu + pristupni red (zaobilazi regularni API). */
    private UUID seedHoneytokenSecret(UUID userId) {
        Secret honey = new Secret();
        honey.setOwnerId(userId);
        honey.setName("honeytoken");
        honey.setEncryptedBlob(randomBytes(40));
        honey.setHoneytoken(true);
        Secret saved = secretRepository.saveAndFlush(honey);

        SecretAccess access = new SecretAccess();
        access.setSecretId(saved.getId());
        access.setUserId(userId);
        access.setWrappedSecretKey(randomBytes(256));
        access.setGrantedById(userId);
        secretAccessRepository.saveAndFlush(access);
        return saved.getId();
    }

    /** Ubacuje red u honeytoken tabelu (za ranjivi SQLi endpoint). */
    private void insertHoneytoken(String label) {
        Honeytoken h = new Honeytoken();
        h.setLabel(label);
        h.setFakeBlob(randomBytes(32));
        honeytokenRepository.saveAndFlush(h);
    }

    /** Pun login tok (register → step1 → TOTP setup/verify → step2); vraća access kolačić. */
    private Cookie login(String username) throws Exception {
        String authKey = register(username);
        String ticket = step1(username, authKey);
        String totpSecret = setupAndEnableTotp(ticket);

        MvcResult step2 = mockMvc.perform(post("/auth/login/step2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("mfaTicket", ticket, "totpCode", currentCode(totpSecret)))))
                .andExpect(status().isOk())
                .andReturn();
        Cookie access = step2.getResponse().getCookie(ACCESS_COOKIE);
        assertThat(access).isNotNull();
        return access;
    }

    /** Registruje korisnika; vraća Base64-kodirani authKey (isti format kao klijent). */
    private String register(String username) throws Exception {
        String authKey = b64(32);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("username", username);
        payload.put("email", username + "@test.local");
        payload.put("kdfSalt", b64(16));
        payload.put("kdfIterations", 600_000);
        payload.put("authKey", authKey);
        payload.put("encUsk", b64(60));
        payload.put("publicKey", b64(294));
        payload.put("encPrivateKey", b64(1245));

        mockMvc.perform(post("/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isCreated());
        return authKey;
    }

    private String step1(String username, String authKey) throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/login/step1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("username", username, "authKey", authKey))))
                .andExpect(status().isOk())
                .andReturn();
        return field(result, "mfaTicket");
    }

    private String setupAndEnableTotp(String ticket) throws Exception {
        MvcResult setup = mockMvc.perform(post("/auth/totp/setup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("mfaTicket", ticket))))
                .andExpect(status().isOk())
                .andReturn();
        String secret = secretFromUri(field(setup, "otpauthUri"));

        mockMvc.perform(post("/auth/totp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("mfaTicket", ticket, "totpCode", currentCode(secret)))))
                .andExpect(status().isNoContent());
        return secret;
    }

    private String currentCode(String secret) {
        try {
            long counter = Math.floorDiv(timeProvider.getTime(), 30);
            return codeGenerator.generate(secret, counter);
        } catch (CodeGenerationException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String secretFromUri(String otpauthUri) {
        return otpauthUri.replaceAll(".*[?&]secret=([^&]+).*", "$1");
    }

    private String field(MvcResult result, String name) throws Exception {
        JsonNode node = objectMapper.readTree(result.getResponse().getContentAsString());
        return node.get(name).asText();
    }

    private static String uniq(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    private static String b64(int n) {
        return B64.encodeToString(randomBytes(n));
    }
}
