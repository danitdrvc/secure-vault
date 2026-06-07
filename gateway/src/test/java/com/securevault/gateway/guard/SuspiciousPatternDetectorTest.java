package com.securevault.gateway.guard;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Faza 9: SQLi / payload detektor. Mora da uhvati očigledne napadačke uzorke (uključujući
 * URL-kodovane), a da NE okine na legitimnim API putanjama.
 */
class SuspiciousPatternDetectorTest {

    private final SuspiciousPatternDetector detector = new SuspiciousPatternDetector();

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/vault/secrets?q=1' or 1=1--",
            "/api/vault/secrets?q=1 UNION SELECT password FROM users",
            "/api/users?id=1;DROP TABLE users",
            "/api/x?q=%27%20OR%201%3D1",            // URL-kodovan ' OR 1=1
            "/api/x?q=1%20union%20select%20x",       // URL-kodovan union select
            "/api/files?path=../../etc/passwd",
            "/api/x?name=<script>alert(1)</script>",
            "/api/x?q=SLEEP(5)"
    })
    void detectsSuspiciousInput(String input) {
        assertThat(detector.isSuspicious(input)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/auth/login/step1",
            "/api/vault/secrets",
            "/api/vault/secrets/3f8b2c1a-0000-0000-0000-000000000000",
            "/api/users/3f8b2c1a-0000-0000-0000-000000000000/public-key",
            "/api/policy",
            "/api/health"
    })
    void allowsLegitimateRequests(String input) {
        assertThat(detector.isSuspicious(input)).isFalse();
    }

    @Test
    void nullAndBlankAreNotSuspicious() {
        assertThat(detector.isSuspicious(null)).isFalse();
        assertThat(detector.isSuspicious("")).isFalse();
    }
}
