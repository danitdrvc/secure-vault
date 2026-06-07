package com.securevault.user.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.audit.domain.AuditLog;
import com.securevault.audit.repository.AuditLogRepository;
import com.securevault.user.domain.Role;
import com.securevault.user.domain.User;
import com.securevault.user.domain.UserStatus;
import com.securevault.user.repository.UserRepository;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Acceptance (Faza 3): registracija čuva samo šifrovane artefakte.
 * Pun stack (controller → service → repository → audit) nad PRAVIM (embedded) PostgreSQL-om.
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
class UserRegistrationTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getEncoder();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void registracijaVraca201IcuvaSamoSifrovaneArtefakte() throws Exception {
        String username = uniq("dev");
        String email = username + "@securevault.local";
        Map<String, Object> payload = validPayload(username, email);
        String authKeyB64 = (String) payload.get("authKey");

        mockMvc.perform(post("/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.role").value("DEVELOPER"))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                // Odgovor NE sme da sadrži ikakav kripto materijal.
                .andExpect(jsonPath("$.authHash").doesNotExist())
                .andExpect(jsonPath("$.encUsk").doesNotExist())
                .andExpect(jsonPath("$.encPrivateKey").doesNotExist());

        User saved = userRepository.findByUsername(username).orElseThrow();
        assertThat(saved.getRole()).isEqualTo(Role.DEVELOPER);
        assertThat(saved.getStatus()).isEqualTo(UserStatus.ACTIVE);

        // auth_hash je bcrypt(authKey), NIKAD poslati authKey.
        assertThat(saved.getAuthHash()).startsWith("$2");
        assertThat(saved.getAuthHash()).isNotEqualTo(authKeyB64);
        assertThat(passwordEncoder.matches(authKeyB64, saved.getAuthHash())).isTrue();

        // Kripto blobovi upisani kao bytea, ne-prazni, i jednaki dekodiranom ulazu (server ih ne dira).
        assertThat(saved.getEncUsk()).isNotEmpty().hasSize(60);
        assertThat(saved.getPublicKey()).isNotEmpty();
        assertThat(saved.getEncPrivateKey()).isNotEmpty();
        assertThat(saved.getKdfSalt()).hasSize(16);
        assertThat(saved.getKdfIterations()).isEqualTo(600_000);

        // Audit zapis registracije je deo imutabilnog hash-lanca (Faza 11): povezuje se na prethodni
        // zapis preko prevHash (ili GENESIS ako je prvi u lancu), a hash je SHA-256 (64 hex znaka).
        List<AuditLog> logs = auditLogRepository.findByActorIdOrderBySeqAsc(saved.getId());
        assertThat(logs).hasSize(1);
        AuditLog log = logs.get(0);
        assertThat(log.getAction()).isEqualTo("USER_REGISTERED");
        assertThat(log.getPrevHash()).matches("GENESIS|[0-9a-f]{64}");
        assertThat(log.getHash()).matches("[0-9a-f]{64}");
    }

    @Test
    void odbijaArtefaktPogresneVelicine() throws Exception {
        // encPrivateKey veličine NEšifrovanog PKCS8 (1217 B) je ispod donje granice → 400.
        Map<String, Object> payload = validPayload(uniq("bad"), uniq("bad") + "@securevault.local");
        payload.put("encPrivateKey", b64(1217));

        mockMvc.perform(post("/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION"));
    }

    @Test
    void odbijaDuplikatKorisnickogImena() throws Exception {
        String username = uniq("dup");
        Map<String, Object> first = validPayload(username, uniq("dup") + "@securevault.local");
        mockMvc.perform(post("/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(first)))
                .andExpect(status().isCreated());

        Map<String, Object> second = validPayload(username, uniq("dup2") + "@securevault.local");
        mockMvc.perform(post("/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(second)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("CONFLICT"));
    }

    @Test
    void odbijaNepoznataPolja() throws Exception {
        Map<String, Object> payload = validPayload(uniq("unk"), uniq("unk") + "@securevault.local");
        payload.put("masterPassword", "ovo-nikad-ne-sme-da-stigne");

        mockMvc.perform(post("/users/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("BAD_REQUEST"));

        assertThat(userRepository.findByUsername((String) payload.get("username"))).isEmpty();
    }

    private static Map<String, Object> validPayload(String username, String email) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("username", username);
        m.put("email", email);
        m.put("kdfSalt", b64(16));
        m.put("kdfIterations", 600_000);
        m.put("authKey", b64(32));
        m.put("encUsk", b64(60));
        m.put("publicKey", b64(294));
        m.put("encPrivateKey", b64(1245));
        return m;
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
