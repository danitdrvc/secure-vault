package com.securevault.vault.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.user.domain.Role;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.securevault.security.JwtCookieAuthenticationFilter.ACCESS_COOKIE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Acceptance (Faza 8): rotacija {@code secretKey}-a. Server zameni blob i re-wrap-uje SVE
 * primaoce; mora dobiti tačno onoliko wrapped ključeva koliko ima pristupnih redova. Pravu
 * kripto-proveru (stari ključ ne otvara nov blob) pokrivaju frontend testovi; ovde se proverava
 * ponašanje endpointa i baze (bajtovi se menjaju, kontrola vlasništva i kompletnost re-wrap-a).
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
class SecretRotationTest {

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
    void vlasnikRotiraTajnuBlobIWrappedSeMenjaju() throws Exception {
        String ownerName = uniq("owner");
        Cookie owner = login(ownerName, Role.DEVELOPER);
        UUID ownerId = userRepository.findByUsername(ownerName).orElseThrow().getId();

        String oldBlob = b64(48);
        String oldWrapped = b64(256);
        String secretId = createSecret(owner, "rotabilna", oldBlob, oldWrapped);

        // Access lista (vlasnik-only) sadrži tačno vlasnika.
        mockMvc.perform(get("/vault/secrets/" + secretId + "/access").cookie(owner))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].userId").value(ownerId.toString()));

        // Rotacija: nov blob + nov wrapped ka vlasniku.
        String newBlob = b64(64);
        String newWrapped = b64(256);
        mockMvc.perform(post("/vault/secrets/" + secretId + "/rotate")
                        .cookie(owner)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("encryptedBlob", newBlob,
                                "wrappedKeys", List.of(wrap(ownerId, newWrapped))))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(secretId));

        Secret stored = secretRepository.findById(UUID.fromString(secretId)).orElseThrow();
        assertThat(stored.getEncryptedBlob()).isEqualTo(B64D.decode(newBlob));
        assertThat(stored.getEncryptedBlob()).isNotEqualTo(B64D.decode(oldBlob));
        assertThat(stored.getRotatedAt()).isAfterOrEqualTo(stored.getCreatedAt());

        SecretAccess access = secretAccessRepository
                .findBySecretIdAndUserId(UUID.fromString(secretId), ownerId).orElseThrow();
        assertThat(access.getWrappedSecretKey()).isEqualTo(B64D.decode(newWrapped));
        assertThat(access.getWrappedSecretKey()).isNotEqualTo(B64D.decode(oldWrapped));
    }

    @Test
    void rotacijaMoraReWrapovatiSvePrimaoce() throws Exception {
        // Team Lead vlasnik deli sa Developer-om → 2 pristupna reda.
        String leadName = uniq("lead");
        Cookie lead = login(leadName, Role.TEAM_LEAD);
        String secretId = createSecret(lead, "deljiva", b64(48), b64(256));

        String devName = uniq("dev");
        login(devName, Role.DEVELOPER);
        UUID recipientId = userRepository.findByUsername(devName).orElseThrow().getId();
        mockMvc.perform(post("/vault/secrets/" + secretId + "/share")
                        .cookie(lead)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("recipientId", recipientId.toString(),
                                "wrappedSecretKey", b64(256)))))
                .andExpect(status().isCreated());

        UUID ownerId = userRepository.findByUsername(leadName).orElseThrow().getId();

        // Rotacija sa SAMO vlasnikovim ključem (nedostaje primalac) → 400, ništa se ne menja.
        byte[] devWrappedBefore = secretAccessRepository
                .findBySecretIdAndUserId(UUID.fromString(secretId), recipientId).orElseThrow()
                .getWrappedSecretKey();

        mockMvc.perform(post("/vault/secrets/" + secretId + "/rotate")
                        .cookie(lead)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("encryptedBlob", b64(64),
                                "wrappedKeys", List.of(wrap(ownerId, b64(256)))))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION"));

        // Primaočev wrapped je netaknut (rotacija odbijena).
        SecretAccess devAfter = secretAccessRepository
                .findBySecretIdAndUserId(UUID.fromString(secretId), recipientId).orElseThrow();
        assertThat(devAfter.getWrappedSecretKey()).isEqualTo(devWrappedBefore);

        // Sa OBA ključa (vlasnik + primalac) rotacija prolazi.
        mockMvc.perform(post("/vault/secrets/" + secretId + "/rotate")
                        .cookie(lead)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("encryptedBlob", b64(64),
                                "wrappedKeys", List.of(wrap(ownerId, b64(256)), wrap(recipientId, b64(256)))))))
                .andExpect(status().isOk());
    }

    @Test
    void neVlasnikNeMozeDaRotiraNitiVidiAccess() throws Exception {
        Cookie owner = login(uniq("owner2"), Role.DEVELOPER);
        String secretId = createSecret(owner, "tuđa", b64(48), b64(256));

        Cookie stranger = login(uniq("stranger"), Role.DEVELOPER);
        mockMvc.perform(get("/vault/secrets/" + secretId + "/access").cookie(stranger))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/vault/secrets/" + secretId + "/rotate")
                        .cookie(stranger)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("encryptedBlob", b64(64),
                                "wrappedKeys", List.of(wrap(UUID.randomUUID(), b64(256)))))))
                .andExpect(status().isForbidden());
    }

    @Test
    void rotacijaNepostojeceTajneVraca404() throws Exception {
        Cookie owner = login(uniq("owner3"), Role.DEVELOPER);
        mockMvc.perform(post("/vault/secrets/" + UUID.randomUUID() + "/rotate")
                        .cookie(owner)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("encryptedBlob", b64(64),
                                "wrappedKeys", List.of(wrap(UUID.randomUUID(), b64(256)))))))
                .andExpect(status().isNotFound());
    }

    // ----- pomoćne metode -----

    private Map<String, Object> wrap(UUID userId, String wrappedSecretKey) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("userId", userId.toString());
        entry.put("wrappedSecretKey", wrappedSecretKey);
        return entry;
    }

    private String createSecret(Cookie access, String name, String blob, String wrapped) throws Exception {
        MvcResult result = mockMvc.perform(post("/vault/secrets")
                        .cookie(access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("name", name, "encryptedBlob", blob, "wrappedSecretKey", wrapped))))
                .andExpect(status().isCreated())
                .andReturn();
        return field(result, "id");
    }

    private Cookie login(String username, Role role) throws Exception {
        String authKey = register(username);
        User user = userRepository.findByUsername(username).orElseThrow();
        user.setRole(role);
        userRepository.saveAndFlush(user);
        return completeLogin(username, authKey);
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

    private Cookie completeLogin(String username, String authKey) throws Exception {
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

    private String json(Object body) throws Exception {
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
