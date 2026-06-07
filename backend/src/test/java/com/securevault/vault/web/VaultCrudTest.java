package com.securevault.vault.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.user.domain.User;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Acceptance (Faza 6): Vault CRUD nad PRAVIM (embedded) PostgreSQL-om, kroz MockMvc i pun
 * security chain. Server vidi samo šifrat — testovi šalju nasumične bajtove kao "šifrate"
 * (enkripcija je klijentska i pokrivena frontend testovima) i proveravaju da se VRAĆAJU
 * netaknuti, da honeytokeni nisu vidljivi, i da kontrola pristupa/vlasništva radi.
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
class VaultCrudTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecretRepository secretRepository;

    @Autowired
    private SecretAccessRepository secretAccessRepository;

    @Test
    void createReadRoundTripVracaNetaknutSifrat() throws Exception {
        Cookie access = login(uniq("owner"));

        String blob = b64(48);
        String wrapped = b64(256);
        String id = createSecret(access, "AWS prod ključ", blob, wrapped);

        // GET vraća isti (neprozirni) šifrat — round-trip bajt-za-bajt.
        mockMvc.perform(get("/vault/secrets/" + id).cookie(access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("AWS prod ključ"))
                .andExpect(jsonPath("$.encryptedBlob").value(blob))
                .andExpect(jsonPath("$.wrappedSecretKey").value(wrapped))
                // Nijedan endpoint NE vraća plaintext.
                .andExpect(jsonPath("$.plaintext").doesNotExist());

        // DB inspekcija: encrypted_blob je tačno ono što je klijent poslao (server ga ne tumači).
        Secret stored = secretRepository.findById(UUID.fromString(id)).orElseThrow();
        assertThat(stored.getEncryptedBlob()).isEqualTo(B64D.decode(blob));
        assertThat(stored.isHoneytoken()).isFalse();
    }

    @Test
    void listaNikadNeVracaHoneytokene() throws Exception {
        String username = uniq("honey");
        Cookie access = login(username);
        UUID userId = userRepository.findByUsername(username).orElseThrow().getId();

        // Prava tajna (kroz API) + honeytoken (ubačen direktno, sa pristupnim redom za korisnika).
        String realId = createSecret(access, "prava", b64(40), b64(256));
        UUID honeyId = seedHoneytoken(userId);

        MvcResult list = mockMvc.perform(get("/vault/secrets").cookie(access))
                .andExpect(status().isOk())
                .andReturn();
        String body = list.getResponse().getContentAsString();
        assertThat(body).contains(realId);
        assertThat(body).doesNotContain(honeyId.toString());

        // Direktan dohvat honeytokena se ponaša kao da ne postoji (404), čak i uz pristupni red.
        mockMvc.perform(get("/vault/secrets/" + honeyId).cookie(access))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));
    }

    @Test
    void korisnikBezPristupaDobija403() throws Exception {
        Cookie ownerAccess = login(uniq("a"));
        String id = createSecret(ownerAccess, "tajna A", b64(40), b64(256));

        Cookie strangerAccess = login(uniq("b"));
        mockMvc.perform(get("/vault/secrets/" + id).cookie(strangerAccess))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));
    }

    @Test
    void updateMenjaNazivIBlob() throws Exception {
        Cookie access = login(uniq("upd"));
        String id = createSecret(access, "stari naziv", b64(40), b64(256));

        String newBlob = b64(64);
        mockMvc.perform(put("/vault/secrets/" + id)
                        .cookie(access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("name", "novi naziv", "encryptedBlob", newBlob))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("novi naziv"));

        mockMvc.perform(get("/vault/secrets/" + id).cookie(access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("novi naziv"))
                .andExpect(jsonPath("$.encryptedBlob").value(newBlob));
    }

    @Test
    void neVlasnikNeMozeDaMenjaNitiBrise() throws Exception {
        Cookie ownerAccess = login(uniq("owner2"));
        String id = createSecret(ownerAccess, "tajna", b64(40), b64(256));

        Cookie strangerAccess = login(uniq("stranger2"));
        mockMvc.perform(put("/vault/secrets/" + id)
                        .cookie(strangerAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("name", "hack", "encryptedBlob", b64(40)))))
                .andExpect(status().isForbidden());
        mockMvc.perform(delete("/vault/secrets/" + id).cookie(strangerAccess))
                .andExpect(status().isForbidden());
    }

    @Test
    void deleteBriseTajnuIPristup() throws Exception {
        Cookie access = login(uniq("del"));
        String id = createSecret(access, "za brisanje", b64(40), b64(256));

        mockMvc.perform(delete("/vault/secrets/" + id).cookie(access))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/vault/secrets/" + id).cookie(access))
                .andExpect(status().isNotFound());
        // Pristupni redovi su takođe uklonjeni.
        assertThat(secretAccessRepository.findBySecretId(UUID.fromString(id))).isEmpty();
    }

    @Test
    void neautentikovanPristupVraca401() throws Exception {
        mockMvc.perform(get("/vault/secrets"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("UNAUTHORIZED"));
    }

    // ----- pomoćne metode -----

    /** Kreira tajnu kroz API; vraća njen id. */
    private String createSecret(Cookie access, String name, String blob, String wrapped) throws Exception {
        MvcResult result = mockMvc.perform(post("/vault/secrets")
                        .cookie(access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("name", name, "encryptedBlob", blob, "wrappedSecretKey", wrapped))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andReturn();
        return field(result, "id");
    }

    /** Ubacuje honeytoken tajnu + pristupni red za korisnika (zaobilazi regularni API). */
    private UUID seedHoneytoken(UUID userId) {
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

    /** Pun login (register → step1 → TOTP setup/verify → step2); vraća access kolačić. */
    private Cookie login(String username) throws Exception {
        String authKey = register(username);
        String ticket = step1(username, authKey);
        String secret = setupAndEnableTotp(ticket);

        MvcResult step2 = mockMvc.perform(post("/auth/login/step2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("mfaTicket", ticket, "totpCode", currentCode(secret)))))
                .andExpect(status().isOk())
                .andReturn();
        Cookie access = step2.getResponse().getCookie(ACCESS_COOKIE);
        assertThat(access).isNotNull();
        return access;
    }

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

    private String step1(String username, String authKey) throws Exception {
        MvcResult result = mockMvc.perform(post("/auth/login/step1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("username", username, "authKey", authKey))))
                .andExpect(status().isOk())
                .andReturn();
        return field(result, "mfaTicket");
    }

    private String setupAndEnableTotp(String ticket) throws Exception {
        MvcResult setup = mockMvc.perform(post("/auth/totp/setup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("mfaTicket", ticket))))
                .andExpect(status().isOk())
                .andReturn();
        String secret = secretFromUri(field(setup, "otpauthUri"));

        mockMvc.perform(post("/auth/totp/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("mfaTicket", ticket, "totpCode", currentCode(secret)))))
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

    private String json(Map<String, ?> body) throws Exception {
        return objectMapper.writeValueAsString(body);
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
