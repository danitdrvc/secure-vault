package com.securevault.gateway.guard;

import com.securevault.gateway.config.GatewayProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Prijavljuje sigurnosne događaje backendu preko internog endpointa {@code /internal/security-events}
 * (zaštićen deljenim {@code X-Internal-Token}). Te rute nisu izložene kroz gateway, pa je poziv
 * čisto server-to-server.
 *
 * <p>Otpornost: ako backend nije dostupan, prijava se TIHO odbacuje ({@code onErrorResume}) —
 * blokiranje IP-a (i {@code 429} klijentu) ne sme da zavisi od dostupnosti audita.
 */
@Service
public class BackendSecurityEventReporter implements SecurityEventReporter {

    private static final Logger log = LoggerFactory.getLogger(BackendSecurityEventReporter.class);

    private final WebClient webClient;
    private final String internalToken;

    public BackendSecurityEventReporter(WebClient.Builder builder, GatewayProperties properties) {
        this.webClient = builder.baseUrl(properties.getBackendUri()).build();
        this.internalToken = properties.getInternalToken();
    }

    @Override
    public Mono<Void> report(String type, String ip, String detailJson) {
        return webClient.post()
                .uri("/internal/security-events")
                .header("X-Internal-Token", internalToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new EventBody(type, ip, detailJson == null ? "{}" : detailJson))
                .retrieve()
                .toBodilessEntity()
                .then()
                .onErrorResume(ex -> {
                    log.warn("Prijava sigurnosnog događaja backendu nije uspela: {}", ex.toString());
                    return Mono.empty();
                });
    }

    /** Telo poziva — imena polja moraju odgovarati backend {@code InternalSecurityEventRequest}. */
    private record EventBody(String type, String ip, String detail) {
    }
}
