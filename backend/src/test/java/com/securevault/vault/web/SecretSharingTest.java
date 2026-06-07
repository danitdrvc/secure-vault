package com.securevault.vault.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.user.domain.Role;
import com.securevault.user.domain.User;
import com.securevault.user.repository.UserRepository;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Acceptance (Faza 7): sigurno deljenje (envelope). Server vidi samo šifrat — testovi šalju
 * nasumične bajtove kao "uvijene ključeve" (pravo re-wrap-ovanje je klijentsko i pokriveno
 * frontend testovima) i proveravaju: deljenje sme samo {@code TEAM_LEAD}, primalac dobija svoj
 * (drugačiji) {@code wrapped_secret_key}, a {@code encrypted_blob} ostaje NEPROMENJEN.
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
class SecretSharingTest {

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
    void teamLeadDeliTajnuPrimalacDobijaSvojWrappedKey() throws Exception {
        String leadName = uniq("lead");
        Cookie lead = login(leadName, Role.TEAM_LEAD);

        String ownerWrapped = b64(256);
        String secretId = createSecret(lead, "deljiva tajna", b64(48), ownerWrapped);

        // Primalac (DEVELOPER).
        String devName = uniq("dev");
        Cookie devAccess = login(devName, Role.DEVELOPER);
        UUID recipientId = userRepository.findByUsername(devName).orElseThrow().getId();

        byte[] blobBefore = secretRepository.findById(UUID.fromString(secretId)).orElseThrow()
                .getEncryptedBlob();

        String recipientWrapped = b64(256);
        mockMvc.perform(post("/vault/secrets/" + secretId + "/share")
                        .cookie(lead)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("recipientId", recipientId.toString(),
                                "wrappedSecretKey", recipientWrapped))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.recipientId").value(recipientId.toString()))
                .andExpect(jsonPath("$.secretId").value(secretId));

        // DB: primaočev wrapped_secret_key je tačno ono što smo poslali, i RAZLIKUJE se od vlasnikovog.
        SecretAccess recipientAccess = secretAccessRepository
                .findBySecretIdAndUserId(UUID.fromString(secretId), recipientId).orElseThrow();
        assertThat(recipientAccess.getWrappedSecretKey()).isEqualTo(B64D.decode(recipientWrapped));
        assertThat(recipientAccess.getWrappedSecretKey()).isNotEqualTo(B64D.decode(ownerWrapped));

        // encrypted_blob je NEPROMENJEN (deljenje ne dira veliki blob).
        byte[] blobAfter = secretRepository.findById(UUID.fromString(secretId)).orElseThrow()
                .getEncryptedBlob();
        assertThat(blobAfter).isEqualTo(blobBefore);

        // Primalac sada vidi tajnu i dobija SVOJ wrapped key kroz GET (ne vlasnikov).
        mockMvc.perform(get("/vault/secrets/" + secretId).cookie(devAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.wrappedSecretKey").value(recipientWrapped));
        mockMvc.perform(get("/vault/secrets").cookie(devAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id=='" + secretId + "')]").exists());
    }

    @Test
    void developerNeMozeDaDeli() throws Exception {
        String ownerName = uniq("owner-dev");
        Cookie owner = login(ownerName, Role.DEVELOPER);
        String secretId = createSecret(owner, "tajna", b64(40), b64(256));

        String devName = uniq("recipient");
        login(devName, Role.DEVELOPER);
        UUID recipientId = userRepository.findByUsername(devName).orElseThrow().getId();

        mockMvc.perform(post("/vault/secrets/" + secretId + "/share")
                        .cookie(owner)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("recipientId", recipientId.toString(),
                                "wrappedSecretKey", b64(256)))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));

        // Deljenje se NIJE desilo.
        assertThat(secretAccessRepository.findBySecretIdAndUserId(UUID.fromString(secretId), recipientId))
                .isEmpty();
    }

    @Test
    void getPublicKeyVracaJavniKljuc() throws Exception {
        String name = uniq("pk");
        Cookie access = login(name, Role.DEVELOPER);
        User user = userRepository.findByUsername(name).orElseThrow();
        String expected = B64.encodeToString(user.getPublicKey());

        mockMvc.perform(get("/users/" + user.getId() + "/public-key").cookie(access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(user.getId().toString()))
                .andExpect(jsonPath("$.publicKey").value(expected));
    }

    @Test
    void getPublicKeyBezSesijeVraca401() throws Exception {
        UUID anyId = UUID.randomUUID();
        mockMvc.perform(get("/users/" + anyId + "/public-key"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deljenjeIstomKorisnikuDvaputVraca409() throws Exception {
        Cookie lead = login(uniq("lead2"), Role.TEAM_LEAD);
        String secretId = createSecret(lead, "tajna", b64(40), b64(256));

        String devName = uniq("dev2");
        login(devName, Role.DEVELOPER);
        UUID recipientId = userRepository.findByUsername(devName).orElseThrow().getId();

        Map<String, Object> body = Map.of("recipientId", recipientId.toString(),
                "wrappedSecretKey", b64(256));

        mockMvc.perform(post("/vault/secrets/" + secretId + "/share")
                        .cookie(lead).contentType(MediaType.APPLICATION_JSON).content(json(body)))
                .andExpect(status().isCreated());
        mockMvc.perform(post("/vault/secrets/" + secretId + "/share")
                        .cookie(lead).contentType(MediaType.APPLICATION_JSON).content(json(body)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("CONFLICT"));
    }

    @Test
    void nepostojeciPrimalacVraca404() throws Exception {
        Cookie lead = login(uniq("lead3"), Role.TEAM_LEAD);
        String secretId = createSecret(lead, "tajna", b64(40), b64(256));

        mockMvc.perform(post("/vault/secrets/" + secretId + "/share")
                        .cookie(lead)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("recipientId", UUID.randomUUID().toString(),
                                "wrappedSecretKey", b64(256)))))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));
    }

    @Test
    void teamLeadBezPristupaTajniNeMozeDaDeli() throws Exception {
        // Vlasnik kreira tajnu.
        Cookie owner = login(uniq("owner3"), Role.TEAM_LEAD);
        String secretId = createSecret(owner, "tuđa tajna", b64(40), b64(256));

        // Drugi Team Lead (bez pristupnog reda) pokuša da je deli → 403 (nema secretKey).
        Cookie otherLead = login(uniq("lead-no-access"), Role.TEAM_LEAD);
        String devName = uniq("dev3");
        login(devName, Role.DEVELOPER);
        UUID recipientId = userRepository.findByUsername(devName).orElseThrow().getId();

        mockMvc.perform(post("/vault/secrets/" + secretId + "/share")
                        .cookie(otherLead)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("recipientId", recipientId.toString(),
                                "wrappedSecretKey", b64(256)))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));
    }

    // ----- pomoćne metode -----

    private String createSecret(Cookie access, String name, String blob, String wrapped) throws Exception {
        MvcResult result = mockMvc.perform(post("/vault/secrets")
                        .cookie(access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("name", name, "encryptedBlob", blob, "wrappedSecretKey", wrapped))))
                .andExpect(status().isCreated())
                .andReturn();
        return field(result, "id");
    }

    /** Registruje korisnika, postavi mu ulogu, pa odradi pun login; vraća access kolačić. */
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
