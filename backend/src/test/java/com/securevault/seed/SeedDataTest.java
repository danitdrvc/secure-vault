package com.securevault.seed;

import com.securevault.honeypot.repository.HoneytokenRepository;
import com.securevault.policy.repository.SecurityPolicyRepository;
import com.securevault.support.EmbeddedPostgresJpaTest;
import com.securevault.user.domain.Role;
import com.securevault.user.domain.User;
import com.securevault.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Acceptance (Faza 1): seed prolazi —
 * count(*) FROM security_policy WHERE is_active = true == 1, admin i honeytokeni postoje.
 */
@EmbeddedPostgresJpaTest
class SeedDataTest {

    @Autowired
    private SecurityPolicyRepository policyRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private HoneytokenRepository honeytokenRepository;

    @Test
    void tacnoJednaAktivnaPolitika() {
        assertThat(policyRepository.countByActiveTrue()).isEqualTo(1L);
        assertThat(policyRepository.findFirstByActiveTrue()).isPresent();
    }

    @Test
    void adminNalogPosejan() {
        Optional<User> admin = userRepository.findByUsername("admin");
        assertThat(admin).isPresent();
        assertThat(admin.get().getRole()).isEqualTo(Role.ADMIN);
        // Placeholder kripto polja MORAJU biti popunjena (NOT NULL), ali su nasumična.
        assertThat(admin.get().getEncUsk()).isNotEmpty();
        assertThat(admin.get().getKdfSalt()).isNotEmpty();
    }

    @Test
    void honeytokeniPosejani() {
        assertThat(honeytokenRepository.count()).isGreaterThanOrEqualTo(3L);
    }
}
