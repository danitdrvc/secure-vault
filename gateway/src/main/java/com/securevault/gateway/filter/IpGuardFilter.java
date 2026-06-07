package com.securevault.gateway.filter;

import com.securevault.gateway.guard.ClientIp;
import com.securevault.gateway.guard.IpReputationService;
import com.securevault.gateway.guard.SecurityEventReporter;
import com.securevault.gateway.guard.SuspiciousPatternDetector;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * Brani jedinu ulaznu tačku (Faza 9): broji "strike"-ove po IP-u i privremeno blokira izvore
 * koji prelaze prag.
 *
 * <p>Strike se podiže na:
 * <ul>
 *   <li><b>neuspeo login</b> — odgovor {@code 401} na {@code /api/auth/login/**} (brute-force);</li>
 *   <li><b>sumnjiv unos</b> — SQLi / payload uzorak u putanji ili query-ju
 *       ({@link SuspiciousPatternDetector}).</li>
 * </ul>
 *
 * <p>Kad strike-ovi pređu prag, IP se blokira na konfigurisani period i naredni zahtevi dobijaju
 * {@code 429}; tačno na tranziciji u blok prijavljuje se {@code IP_BLOCKED} događaj backendu.
 * Sumnjiv zahtev se NE odbija odmah na nivou gateway-a (samo se broji) — tako honeypot okidač iz
 * Faze 10 i dalje može da uhvati prvi pokušaj, dok upornog napadača blokira akumulacija strike-ova.
 *
 * <p>Dekripcione greške se ne broje ovde: one su klijentske (zero-knowledge) i gateway ih ne vidi.
 * Isteknute sesije ({@code 401} van login-a) se namerno ne broje da legitiman neaktivan korisnik
 * ne bi bio blokiran.
 */
@Component
public class IpGuardFilter implements GlobalFilter, Ordered {

    private static final String LOGIN_PATH_PREFIX = "/api/auth/login";
    private static final String IP_BLOCKED = "IP_BLOCKED";

    private final IpReputationService reputation;
    private final SuspiciousPatternDetector detector;
    private final SecurityEventReporter reporter;

    public IpGuardFilter(IpReputationService reputation,
                         SuspiciousPatternDetector detector,
                         SecurityEventReporter reporter) {
        this.reputation = reputation;
        this.detector = detector;
        this.reporter = reporter;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String ip = ClientIp.resolve(exchange);

        return reputation.isBlocked(ip).flatMap(blocked -> {
            if (Boolean.TRUE.equals(blocked)) {
                return rejectBlocked(exchange);
            }

            Mono<Void> preStrike = isSuspicious(exchange)
                    ? strike(ip, "SUSPICIOUS_INPUT", pathAndQuery(exchange.getRequest()))
                    : Mono.empty();

            return preStrike.then(
                    chain.filter(exchange)
                            .then(Mono.defer(() -> postProcess(exchange, ip))));
        });
    }

    /** Posle proxy-ja: neuspeo login ({@code 401} na login putanji) podiže strike. */
    private Mono<Void> postProcess(ServerWebExchange exchange, String ip) {
        ServerHttpRequest request = exchange.getRequest();
        HttpStatusCode status = exchange.getResponse().getStatusCode();
        boolean failedLogin = request.getURI().getRawPath().startsWith(LOGIN_PATH_PREFIX)
                && status != null && status.value() == HttpStatus.UNAUTHORIZED.value();
        if (failedLogin) {
            return strike(ip, "FAILED_LOGIN", request.getURI().getRawPath());
        }
        return Mono.empty();
    }

    /** Registruj strike; ako je IP ovim UPRAVO blokiran, prijavi {@code IP_BLOCKED} backendu. */
    private Mono<Void> strike(String ip, String reason, String resource) {
        return reputation.registerStrike(ip)
                .flatMap(justBlocked -> Boolean.TRUE.equals(justBlocked)
                        ? reporter.report(IP_BLOCKED, ip, detailJson(reason, resource))
                        : Mono.empty());
    }

    private boolean isSuspicious(ServerWebExchange exchange) {
        return detector.isSuspicious(pathAndQuery(exchange.getRequest()));
    }

    private static String pathAndQuery(ServerHttpRequest request) {
        String path = request.getURI().getRawPath();
        String query = request.getURI().getRawQuery();
        return query == null || query.isBlank() ? path : path + "?" + query;
    }

    private Mono<Void> rejectBlocked(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = ("{\"error\":{\"code\":\"" + IP_BLOCKED
                + "\",\"message\":\"Privremeno blokirano zbog sumnjive aktivnosti.\"}}")
                .getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(body);
        return response.writeWith(Mono.just(buffer));
    }

    private static String detailJson(String reason, String resource) {
        return "{\"reason\":\"" + escape(reason) + "\",\"resource\":\"" + escape(resource) + "\"}";
    }

    /** Minimalno JSON-escapovanje da detalj ostane validan jsonb (kolona na backendu). */
    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Override
    public int getOrder() {
        // Najveći prioritet: blok-provera se izvrši pre rute/rate-limitera, a post-obrada
        // (.then) tek kad ceo lanac završi i status odgovora je poznat.
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
