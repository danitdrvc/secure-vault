package com.securevault.gateway.guard;

import reactor.core.publisher.Mono;

/**
 * Reputacija IP adrese (brute-force / sumnjiva aktivnost) — apstrakcija nad Redis brojačima,
 * da {@link IpGuardFilter} bude testabilan bez živog Redis-a.
 */
public interface IpReputationService {

    /** Da li je IP trenutno (privremeno) blokiran. */
    Mono<Boolean> isBlocked(String ip);

    /**
     * Registruje jedan "strike" (neuspeo login ili sumnjiv zahtev).
     *
     * @return {@code true} ako je IP ovim strike-om UPRAVO prešao prag i postao blokiran
     *         (tranzicija — koristi se da se {@code IP_BLOCKED} događaj prijavi tačno jednom);
     *         {@code false} ako prag još nije dostignut ili je IP već bio blokiran.
     */
    Mono<Boolean> registerStrike(String ip);
}
