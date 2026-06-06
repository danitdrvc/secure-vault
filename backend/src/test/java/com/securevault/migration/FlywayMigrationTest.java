package com.securevault.migration;

import com.securevault.support.EmbeddedPostgresJpaTest;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Acceptance (Faza 1): "flyway info pokazuje sve migracije primenjene (Success)".
 */
@EmbeddedPostgresJpaTest
class FlywayMigrationTest {

    @Autowired
    private Flyway flyway;

    @Test
    void sveMigracijePrimenjeneBezPending() {
        var info = flyway.info();

        assertThat(info.pending())
                .as("ne sme biti neprimenjenih (pending) migracija")
                .isEmpty();

        MigrationInfo[] applied = info.applied();
        assertThat(applied)
                .as("V1 i V2 moraju biti primenjene")
                .hasSizeGreaterThanOrEqualTo(2);
        assertThat(applied)
                .allSatisfy(m -> assertThat(m.getState().isApplied()).isTrue());

        assertThat(Arrays.stream(applied).map(m -> m.getVersion().getVersion()).toList())
                .contains("1", "2");
    }
}
