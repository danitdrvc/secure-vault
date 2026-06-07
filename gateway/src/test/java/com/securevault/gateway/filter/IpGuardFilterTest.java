package com.securevault.gateway.filter;

import com.securevault.gateway.guard.IpReputationService;
import com.securevault.gateway.guard.SecurityEventReporter;
import com.securevault.gateway.guard.SuspiciousPatternDetector;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Faza 9 — IpGuardFilter ponašanje, izolovano od Redis-a/backenda preko in-memory fake-ova
 * ({@link FakeReputation}, {@link RecordingReporter}) koji prate semantiku produkcionih
 * implementacija (strike-brojač + tranzicija u blok).
 */
class IpGuardFilterTest {

    private final SuspiciousPatternDetector detector = new SuspiciousPatternDetector();

    /** Acceptance: N+1 uzastopnih neuspešnih login-a sa istog IP → 429 + IP_BLOCKED događaj. */
    @Test
    void failedLoginsReachThresholdThenBlockWith429AndEvent() {
        int n = 3;
        FakeReputation reputation = new FakeReputation(n);
        RecordingReporter reporter = new RecordingReporter();
        IpGuardFilter filter = new IpGuardFilter(reputation, detector, reporter);

        GatewayFilterChain failChain = ex -> {
            ex.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return Mono.empty();
        };

        // Prvih N login pokušaja: backend vraća 401 (neuspeo login), gateway propušta.
        for (int i = 0; i < n; i++) {
            MockServerWebExchange exchange = loginExchange("1.1.1.1");
            filter.filter(exchange, failChain).block();
            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }

        // Tačno jedan IP_BLOCKED je prijavljen na tranziciji.
        assertThat(reporter.events).containsExactly("IP_BLOCKED:1.1.1.1");

        // (N+1)-vi zahtev: IP je blokiran -> 429, backend se NE poziva.
        AtomicBoolean backendCalled = new AtomicBoolean(false);
        GatewayFilterChain spyChain = ex -> {
            backendCalled.set(true);
            return Mono.empty();
        };
        MockServerWebExchange blocked = loginExchange("1.1.1.1");
        filter.filter(blocked, spyChain).block();

        assertThat(blocked.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(backendCalled).isFalse();
        // Blok se prijavljuje samo jednom (ne na svaki naredni 429).
        assertThat(reporter.events).containsExactly("IP_BLOCKED:1.1.1.1");
    }

    /** Sumnjiv unos (SQLi uzorak) podiže strike; po pragu blokira IP i prijavljuje događaj. */
    @Test
    void suspiciousInputRaisesStrikeAndBlocks() {
        FakeReputation reputation = new FakeReputation(1);
        RecordingReporter reporter = new RecordingReporter();
        IpGuardFilter filter = new IpGuardFilter(reputation, detector, reporter);

        GatewayFilterChain okChain = ex -> {
            ex.getResponse().setStatusCode(HttpStatus.OK);
            return Mono.empty();
        };

        MockServerWebExchange suspicious = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/vault/secrets")
                        .queryParam("q", "1 union select password from users")
                        .remoteAddress(new InetSocketAddress("9.9.9.9", 12345)));
        filter.filter(suspicious, okChain).block();

        assertThat(reporter.events).containsExactly("IP_BLOCKED:9.9.9.9");

        // Naredni (čak i bezopasan) zahtev sa istog IP → 429.
        AtomicBoolean backendCalled = new AtomicBoolean(false);
        MockServerWebExchange next = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/vault/secrets")
                        .remoteAddress(new InetSocketAddress("9.9.9.9", 12346)));
        filter.filter(next, ex -> {
            backendCalled.set(true);
            return Mono.empty();
        }).block();

        assertThat(next.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(backendCalled).isFalse();
    }

    /** Legitiman saobraćaj ispod praga nije pogođen: prolazi do backenda, bez bloka/događaja. */
    @Test
    void legitimateTrafficBelowThresholdPasses() {
        FakeReputation reputation = new FakeReputation(5);
        RecordingReporter reporter = new RecordingReporter();
        IpGuardFilter filter = new IpGuardFilter(reputation, detector, reporter);

        AtomicBoolean backendCalled = new AtomicBoolean(false);
        GatewayFilterChain okChain = ex -> {
            backendCalled.set(true);
            ex.getResponse().setStatusCode(HttpStatus.OK);
            return Mono.empty();
        };

        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/api/vault/secrets")
                        .remoteAddress(new InetSocketAddress("2.2.2.2", 4444)));
        filter.filter(exchange, okChain).block();

        assertThat(backendCalled).isTrue();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(reporter.events).isEmpty();
        assertThat(reputation.isBlocked("2.2.2.2").block()).isFalse();
    }

    /** Uspešan login (200) ne podiže strike — samo 401 na login putanji se broji. */
    @Test
    void successfulLoginDoesNotStrike() {
        FakeReputation reputation = new FakeReputation(3);
        RecordingReporter reporter = new RecordingReporter();
        IpGuardFilter filter = new IpGuardFilter(reputation, detector, reporter);

        GatewayFilterChain okChain = ex -> {
            ex.getResponse().setStatusCode(HttpStatus.OK);
            return Mono.empty();
        };

        for (int i = 0; i < 10; i++) {
            filter.filter(loginExchange("3.3.3.3"), okChain).block();
        }

        assertThat(reporter.events).isEmpty();
        assertThat(reputation.isBlocked("3.3.3.3").block()).isFalse();
    }

    private static MockServerWebExchange loginExchange(String ip) {
        return MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/auth/login/step1")
                        .remoteAddress(new InetSocketAddress(ip, 5555)));
    }

    /** In-memory reputacija: prati semantiku {@code RedisIpReputationService} (strike + tranzicija). */
    private static final class FakeReputation implements IpReputationService {
        private final int maxStrikes;
        private final Map<String, Integer> strikes = new HashMap<>();
        private final Set<String> blocked = new HashSet<>();

        FakeReputation(int maxStrikes) {
            this.maxStrikes = maxStrikes;
        }

        @Override
        public Mono<Boolean> isBlocked(String ip) {
            return Mono.just(blocked.contains(ip));
        }

        @Override
        public Mono<Boolean> registerStrike(String ip) {
            int count = strikes.merge(ip, 1, Integer::sum);
            if (count >= maxStrikes) {
                // true samo na PRVOM prelasku praga (kao Redis SET NX).
                return Mono.just(blocked.add(ip));
            }
            return Mono.just(false);
        }
    }

    private static final class RecordingReporter implements SecurityEventReporter {
        private final List<String> events = new ArrayList<>();

        @Override
        public Mono<Void> report(String type, String ip, String detailJson) {
            events.add(type + ":" + ip);
            return Mono.empty();
        }
    }
}
