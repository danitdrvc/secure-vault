package com.securevault.user.repository;

import com.securevault.support.EmbeddedPostgresJpaTest;
import com.securevault.user.domain.Role;
import com.securevault.user.domain.User;
import com.securevault.user.domain.UserStatus;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.SecureRandom;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Acceptance (Faza 1): @DataJpaTest — repozitorijum može da kreira i pročita User red.
 */
@EmbeddedPostgresJpaTest
class UserRepositoryTest {

    private static final SecureRandom RNG = new SecureRandom();

    @Autowired
    private UserRepository userRepository;

    @Test
    void kreirajIProcitajKorisnika() {
        User user = new User();
        user.setUsername("dev1");
        user.setEmail("dev1@securevault.local");
        user.setRole(Role.DEVELOPER);
        user.setStatus(UserStatus.ACTIVE);
        user.setKdfSalt(randomBytes(16));
        user.setAuthHash("$2a$10$testtesttesttesttesttesttesttesttesttesttesttestte");
        user.setEncUsk(randomBytes(64));
        user.setPublicKey(randomBytes(64));
        user.setEncPrivateKey(randomBytes(64));

        User saved = userRepository.saveAndFlush(user);
        assertThat(saved.getId()).isNotNull();

        UUID id = saved.getId();
        Optional<User> found = userRepository.findById(id);

        assertThat(found).isPresent();
        assertThat(found.get().getUsername()).isEqualTo("dev1");
        assertThat(found.get().getRole()).isEqualTo(Role.DEVELOPER);
        assertThat(found.get().getKdfIterations()).isEqualTo(600_000);
        assertThat(found.get().getCreatedAt()).isNotNull();
        assertThat(found.get().getEncPrivateKey()).hasSize(64);
    }

    @Test
    void findByUsernameRadi() {
        User user = new User();
        user.setUsername("lookup-user");
        user.setEmail("lookup@securevault.local");
        user.setKdfSalt(randomBytes(16));
        user.setAuthHash("$2a$10$testtesttesttesttesttesttesttesttesttesttesttestte");
        user.setEncUsk(randomBytes(64));
        user.setPublicKey(randomBytes(64));
        user.setEncPrivateKey(randomBytes(64));
        userRepository.saveAndFlush(user);

        assertThat(userRepository.findByUsername("lookup-user")).isPresent();
        assertThat(userRepository.existsByEmail("lookup@securevault.local")).isTrue();
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }
}
