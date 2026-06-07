package com.securevault.gateway.guard;

import reactor.core.publisher.Mono;

/**
 * Prijava sigurnosnog događaja (npr. {@code IP_BLOCKED}) trajnom skladištu.
 * Apstrakcija da {@link IpGuardFilter} bude testabilan bez živog backenda.
 */
public interface SecurityEventReporter {

    /**
     * @param type       tip događaja ({@code IP_BLOCKED}, ...)
     * @param ip         IP izvora
     * @param detailJson dodatni detalji kao JSON string ({@code "{}"} ako prazno)
     */
    Mono<Void> report(String type, String ip, String detailJson);
}
