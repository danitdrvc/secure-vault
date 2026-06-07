package com.securevault.auth.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.user.domain.User;
import com.securevault.user.repository.UserRepository;
import com.securevault.vault.domain.Secret;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Acceptance (Faza 8): promena master lozinke ({@code POST /auth/rotate-master}). Server prima
 * samo re-šifrovane artefakte + step-up dokaz STARE lozinke; menja {@code auth_hash}/{@code encUsk}
 * (USK ostaje isti → blobovi tajni su NETAKNUTI). Pravu kripto-rekonstrukciju pokrivaju frontend
 * testovi; ovde se proverava ponašanje endpointa i baze.
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
class MasterRotationTest {

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

    @Test
    void rotacijaMenjaAuthIEncUskAliNeDiraTajne() throws Exception {
        String username = uniq("rot");
        String oldAuthKey = register(username);
        Cookie access = completeLogin(username, oldAuthKey);

        // Tajna pre promene lozinke — njen blob mora ostati netaknut.
        String blob = b64(48);
        String secretId = createSecret(access, "tajna pre promene", blob, b64(256));
        byte[] encUskBefore = userRepository.findByUsername(username).orElseThrow().getEncUsk();

        // Promena lozinke: novi authKey + novi (re-šifrovani) artefakti; dokaz stare lozinke je validan.
        String newAuthKey = b64(32);
        String newEncUsk = b64(60);
        mockMvc.perform(post("/auth/rotate-master")
                        .cookie(access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(rotateBody(oldAuthKey, newAuthKey, newEncUsk, b64(1245)))))
                .andExpect(status().isNoContent());

        User after = userRepository.findByUsername(username).orElseThrow();
        // auth_hash je novi (stari authKey više ne odgovara, novi odgovara) i encUsk je promenjen.
        assertThat(after.getEncUsk()).isNotEqualTo(encUskBefore);
        assertThat(after.getEncUsk()).isEqualTo(B64D.decode(newEncUsk));

        // Stara lozinka više ne radi; nova radi (step1).
        mockMvc.perform(post("/auth/login/step1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("username", username, "authKey", oldAuthKey))))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/auth/login/step1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("username", username, "authKey", newAuthKey))))
                .andExpect(status().isOk());

        // Blob tajne je NETAKNUT (promena lozinke ne dira tajne — USK je isti).
        Secret stored = secretRepository.findById(UUID.fromString(secretId)).orElseThrow();
        assertThat(stored.getEncryptedBlob()).isEqualTo(B64D.decode(blob));
    }

    @Test
    void pogresnaTrenutnaLozinkaOdbijaRotaciju() throws Exception {
        String username = uniq("rot-bad");
        String oldAuthKey = register(username);
        Cookie access = completeLogin(username, oldAuthKey);
        byte[] encUskBefore = userRepository.findByUsername(username).orElseThrow().getEncUsk();

        // currentAuthKey ≠ stvarni → 401, ništa se ne menja.
        mockMvc.perform(post("/auth/rotate-master")
                        .cookie(access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(rotateBody(b64(32), b64(32), b64(60), b64(1245)))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("UNAUTHORIZED"));

        User after = userRepository.findByUsername(username).orElseThrow();
        assertThat(after.getEncUsk()).isEqualTo(encUskBefore);
        // Stara lozinka i dalje radi (auth_hash nepromenjen).
        mockMvc.perform(post("/auth/login/step1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("username", username, "authKey", oldAuthKey))))
                .andExpect(status().isOk());
    }

    @Test
    void rotacijaBezSesijeVraca401() throws Exception {
        mockMvc.perform(post("/auth/rotate-master")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(rotateBody(b64(32), b64(32), b64(60), b64(1245)))))
                .andExpect(status().isUnauthorized());
    }

    // ----- pomoćne metode -----

    private Map<String, Object> rotateBody(String currentAuthKey, String authKey, String encUsk, String encPrivateKey) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("currentAuthKey", currentAuthKey);
        body.put("authKey", authKey);
        body.put("kdfSalt", b64(16));
        body.put("kdfIterations", 600_000);
        body.put("encUsk", encUsk);
        body.put("encPrivateKey", encPrivateKey);
        return body;
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

    private static String b64(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return B64.encodeToString(b);
    }
}
