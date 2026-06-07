package com.securevault.policy.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.policy.domain.SecurityPolicy;
import com.securevault.policy.repository.SecurityPolicyRepository;
import com.securevault.user.domain.Role;
import com.securevault.user.domain.User;
import com.securevault.user.repository.UserRepository;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Acceptance (Faza 8): admin upravljanje nalozima i politikom. Admin SAMO aktivira/deaktivira
 * naloge i menja sigurnosnu politiku ({@code @PreAuthorize ADMIN}); deaktiviran korisnik ne može
 * da se uloguje ({@code 403} u step1). Pun stack nad embedded PostgreSQL-om, kroz MockMvc.
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
class AdminPolicyTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getEncoder();

    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityPolicyRepository policyRepository;

    /** Vrati politiku na default vrednosti (deljeni singleton red; testovi je menjaju). */
    @BeforeEach
    void resetPolicy() {
        SecurityPolicy policy = policyRepository.findFirstByActiveTrue().orElseThrow();
        policy.setMinMasterPwLength(12);
        policy.setDefaultRotationDays(90);
        policy.setAccessTokenTtlSec(300);
        policy.setRefreshTokenTtlSec(3600);
        policy.setSessionMaxTtlSec(1800);
        policy.setHoneypotEndpoint(false);
        policyRepository.saveAndFlush(policy);
    }

    @Test
    void adminDeaktiviraNalogKojiViseNeMozeDaSeUloguje() throws Exception {
        String devName = uniq("dev");
        String devAuthKey = register(devName);
        UUID devId = userRepository.findByUsername(devName).orElseThrow().getId();
        // Dev se pre deaktivacije može ulogovati (step1 prolazi).
        step1Ok(devName, devAuthKey);

        Cookie admin = login(uniq("admin"), Role.ADMIN);

        mockMvc.perform(patch("/admin/users/" + devId + "/status")
                        .cookie(admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("status", "DEACTIVATED"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DEACTIVATED"));

        // Deaktiviran nalog → step1 vraća 403 (nalog nije aktivan).
        mockMvc.perform(post("/auth/login/step1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("username", devName, "authKey", devAuthKey))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));

        // Admin reaktivira → step1 ponovo prolazi.
        mockMvc.perform(patch("/admin/users/" + devId + "/status")
                        .cookie(admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("status", "ACTIVE"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"));
        step1Ok(devName, devAuthKey);
    }

    @Test
    void developerNeMozeDaMenjaStatus() throws Exception {
        String devName = uniq("dev-no-admin");
        Cookie dev = login(devName, Role.DEVELOPER);
        UUID devId = userRepository.findByUsername(devName).orElseThrow().getId();

        // Method security (@PreAuthorize ADMIN) odbija PRE ulaska u servis → 403.
        mockMvc.perform(patch("/admin/users/" + devId + "/status")
                        .cookie(dev)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("status", "DEACTIVATED"))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));
    }

    @Test
    void adminNeMozePostavitiFrozen() throws Exception {
        String devName = uniq("dev-frozen");
        register(devName);
        UUID devId = userRepository.findByUsername(devName).orElseThrow().getId();
        Cookie admin = login(uniq("admin2"), Role.ADMIN);

        // FROZEN je rezervisan za honeypot okidač (Faza 10) — admin ga ne postavlja ručno → 400.
        mockMvc.perform(patch("/admin/users/" + devId + "/status")
                        .cookie(admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("status", "FROZEN"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION"));
    }

    @Test
    void adminMenjaPolitikuPaSeIzmenaVidi() throws Exception {
        Cookie admin = login(uniq("admin3"), Role.ADMIN);

        Map<String, Object> patch = new LinkedHashMap<>();
        patch.put("minMasterPwLength", 16);
        patch.put("defaultRotationDays", 30);
        patch.put("sessionMaxTtlSec", 2400);

        mockMvc.perform(patch("/admin/policy")
                        .cookie(admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(patch)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.minMasterPwLength").value(16))
                .andExpect(jsonPath("$.defaultRotationDays").value(30))
                .andExpect(jsonPath("$.sessionMaxTtlSec").value(2400))
                // Nepromenjeno polje ostaje default.
                .andExpect(jsonPath("$.accessTokenTtlSec").value(300));

        mockMvc.perform(get("/admin/policy").cookie(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.minMasterPwLength").value(16));

        // DB ogledalo.
        SecurityPolicy stored = policyRepository.findFirstByActiveTrue().orElseThrow();
        assertThat(stored.getMinMasterPwLength()).isEqualTo(16);
        assertThat(stored.getDefaultRotationDays()).isEqualTo(30);
    }

    @Test
    void klijentVidiSamoPodskupPolitike() throws Exception {
        Cookie dev = login(uniq("dev-policy"), Role.DEVELOPER);

        mockMvc.perform(get("/policy").cookie(dev))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.minMasterPwLength").value(12))
                .andExpect(jsonPath("$.defaultRotationDays").value(90))
                // Tehnička podešavanja sesije/tokena NISU u klijentskom pogledu.
                .andExpect(jsonPath("$.accessTokenTtlSec").doesNotExist())
                .andExpect(jsonPath("$.sessionMaxTtlSec").doesNotExist());
    }

    @Test
    void developerNeMozeAdminPolicy() throws Exception {
        Cookie dev = login(uniq("dev-policy2"), Role.DEVELOPER);

        mockMvc.perform(get("/admin/policy").cookie(dev))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));
        mockMvc.perform(patch("/admin/policy")
                        .cookie(dev)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("minMasterPwLength", 20))))
                .andExpect(status().isForbidden());
    }

    @Test
    void neautentikovanPristupAdminRutamaVraca401() throws Exception {
        mockMvc.perform(get("/admin/policy"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(patch("/admin/users/" + UUID.randomUUID() + "/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("status", "ACTIVE"))))
                .andExpect(status().isUnauthorized());
    }

    // ----- pomoćne metode -----

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

    private void step1Ok(String username, String authKey) throws Exception {
        mockMvc.perform(post("/auth/login/step1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("username", username, "authKey", authKey))))
                .andExpect(status().isOk());
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
