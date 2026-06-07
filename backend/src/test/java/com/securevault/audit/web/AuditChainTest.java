package com.securevault.audit.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.audit.domain.AuditLog;
import com.securevault.audit.repository.AuditAnchorRepository;
import com.securevault.audit.repository.AuditLogRepository;
import com.securevault.audit.service.AuditService;
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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
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
 * Acceptance (Faza 11): imutabilni audit log (hash lanac + anchoring).
 *
 * <p>Pokriva:
 * <ul>
 *   <li>{@code verifyChain()} = true na netaknutom lancu (i kroz {@code GET /admin/audit/verify}).
 *   <li>Ručna izmena {@code metadata} jednog zapisa u bazi → {@code verifyChain()} = false,
 *       sa tačnim {@code brokenAtSeq}; restauracija vrati lanac u ispravno stanje.
 *   <li>Anchoring ({@code POST /admin/audit/anchor}) upiše {@code audit_anchor} red sa
 *       {@code headHash}-om i pošalje ga na kanal (u testu: log, bez konfigurisanog mail-a).
 *   <li>Append-only: nema UPDATE/DELETE ruta nad {@code audit_log}; verifikacija je samo ADMIN.
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
class AuditChainTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getEncoder();

    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired UserRepository userRepository;
    @Autowired AuditService auditService;
    @Autowired AuditLogRepository auditLogRepository;
    @Autowired AuditAnchorRepository auditAnchorRepository;
    @Autowired JdbcTemplate jdbcTemplate;

    // ----- 1. verifyChain() = true na netaknutom lancu -----

    @Test
    void verifikacijaJeTacnaNaNetaknutomLancu() throws Exception {
        // Registracija + login generišu prave audit zapise kroz lanac (USER_REGISTERED, TOTP_ENABLED, LOGIN_SUCCESS).
        Cookie admin = login(uniq("audit-admin"), Role.ADMIN);

        assertThat(auditLogRepository.count()).isGreaterThanOrEqualTo(3);
        assertThat(auditService.verifyChain()).isTrue();

        mockMvc.perform(get("/admin/audit/verify").cookie(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.brokenAtSeq").doesNotExist())
                .andExpect(jsonPath("$.verifiedCount").isNumber());
    }

    // ----- 2. Ručna izmena metadata u bazi obara verifikaciju -----

    @Test
    void rucnaIzmenaMetadataObaraVerifikaciju() throws Exception {
        Cookie admin = login(uniq("audit-tamper"), Role.ADMIN);
        assertThat(auditService.verifyChain()).isTrue();

        // Uzmi najstariji zapis i ZAOBIĐI append-only API (direktan SQL UPDATE nad bazom).
        AuditLog target = auditLogRepository.findAllByOrderBySeqAsc().get(0);
        String originalMetadata = target.getMetadata();
        long tamperedSeq = target.getSeq();

        jdbcTemplate.update("UPDATE audit_log SET metadata = ?::jsonb WHERE id = ?::uuid",
                "{\"tampered\":\"injected\"}", target.getId().toString());

        // Lanac je sada nekonzistentan od tog seq nadalje.
        assertThat(auditService.verifyChain()).isFalse();
        assertThat(auditService.verify().valid()).isFalse();
        assertThat(auditService.verify().brokenAtSeq()).isEqualTo(tamperedSeq);

        mockMvc.perform(get("/admin/audit/verify").cookie(admin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.brokenAtSeq").value(tamperedSeq));

        // Restauracija originalne vrednosti vraća lanac u ispravno stanje (kanonikalizacija je idempotentna).
        jdbcTemplate.update("UPDATE audit_log SET metadata = ?::jsonb WHERE id = ?::uuid",
                originalMetadata, target.getId().toString());
        assertThat(auditService.verifyChain()).isTrue();
    }

    // ----- 3. Anchoring upiše red i pošalje headHash na kanal -----

    @Test
    void sidrenjeKreiraRedSaHeadHashom() throws Exception {
        Cookie admin = login(uniq("audit-anchor"), Role.ADMIN);

        AuditLog head = auditLogRepository.findTopByOrderBySeqDesc().orElseThrow();
        long anchorsBefore = auditAnchorRepository.count();

        MvcResult result = mockMvc.perform(post("/admin/audit/anchor").cookie(admin))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.headHash").value(head.getHash()))
                .andExpect(jsonPath("$.toSeq").value(head.getSeq()))
                // Bez konfigurisanog mail-a sidri se na nezavisni log kanal.
                .andExpect(jsonPath("$.channel").value("log"))
                .andReturn();

        assertThat(auditAnchorRepository.count()).isEqualTo(anchorsBefore + 1);

        // Upisani red u bazi nosi tačan headHash.
        String anchorId = field(result, "id");
        var stored = auditAnchorRepository.findById(UUID.fromString(anchorId)).orElseThrow();
        assertThat(stored.getHeadHash()).isEqualTo(head.getHash());
        assertThat(stored.getToSeq()).isEqualTo(head.getSeq());

        // Idempotentno: bez novih zapisa drugo sidrenje nema šta da upiše → 404.
        mockMvc.perform(post("/admin/audit/anchor").cookie(admin))
                .andExpect(status().isNotFound());
    }

    // ----- 4. Append-only: nema mutacionih ruta; verifikacija je samo ADMIN -----

    @Test
    void auditLogJeAppendOnlyIVerifikacijaSamoZaAdmina() throws Exception {
        Cookie dev = login(uniq("audit-dev"), Role.DEVELOPER);
        Cookie admin = login(uniq("audit-admin2"), Role.ADMIN);

        // Developer ne sme da vidi verifikaciju (samo ADMIN).
        mockMvc.perform(get("/admin/audit/verify").cookie(dev))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));

        // Neautentikovan → 401.
        mockMvc.perform(get("/admin/audit/verify"))
                .andExpect(status().isUnauthorized());

        // Nema UPDATE/DELETE ruta nad audit logom (append-only) — čak ni za admina (ruta ne postoji → 404).
        AuditLog any = auditLogRepository.findAllByOrderBySeqAsc().get(0);
        mockMvc.perform(delete("/admin/audit/log/" + any.getId()).cookie(admin))
                .andExpect(status().isNotFound());
        mockMvc.perform(put("/admin/audit/log/" + any.getId()).cookie(admin))
                .andExpect(status().isNotFound());

        // Developer ne sme ni da okine sidrenje.
        mockMvc.perform(post("/admin/audit/anchor").cookie(dev))
                .andExpect(status().isForbidden());
    }

    // ----- Pomoćne metode (isti obrazac kao ostali acceptance testovi) -----

    /** Registruje korisnika, postavi mu ulogu, pa odradi pun login; vraća access kolačić. */
    private Cookie login(String username, Role role) throws Exception {
        String authKey = register(username);
        User user = userRepository.findByUsername(username).orElseThrow();
        user.setRole(role);
        userRepository.saveAndFlush(user);

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

    private static String b64(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return B64.encodeToString(b);
    }
}
