package com.securevault.support;

import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.TestPropertySource;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * JPA slice test nad PRAVIM (embedded) PostgreSQL-om umesto H2 — da Flyway DDL
 * (bytea / jsonb / uuid / pgcrypto) radi identično kao u produkciji, bez Dockera.
 *
 * <p>Tok pri dizanju konteksta: zonky podigne PG binar -> Flyway migrira (V1, V2)
 * -> Hibernate VALIDIRA entitete spram šeme -> test se izvršava (transakcija se rollback-uje).
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Inherited
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@AutoConfigureEmbeddedDatabase(provider = AutoConfigureEmbeddedDatabase.DatabaseProvider.ZONKY)
@ImportAutoConfiguration(FlywayAutoConfiguration.class)
@TestPropertySource(properties = {
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.flyway.enabled=true",
        "spring.flyway.locations=classpath:db/migration"
})
public @interface EmbeddedPostgresJpaTest {
}
