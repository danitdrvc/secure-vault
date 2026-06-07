package com.securevault.gateway.guard;

import com.securevault.gateway.config.GatewayProperties;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Redis-podržana reputacija IP-a (Faza 9).
 *
 * <p>Strike-ovi se broje atomičnim {@code INCR}-om u ključu sa prozorskim TTL-om; kad brojač
 * dostigne prag, postavlja se blok-ključ sa zasebnim TTL-om. Blokiranje koristi {@code SET NX}
 * ({@code setIfAbsent}) pa se tranzicija (prvi put pređen prag) prepoznaje atomično — bez toga
 * bi se {@code IP_BLOCKED} prijavljivao na svaki naredni strike.
 */
@Service
public class RedisIpReputationService implements IpReputationService {

    private static final String STRIKES_PREFIX = "ipguard:strikes:";
    private static final String BLOCK_PREFIX = "ipguard:blocked:";

    private final ReactiveStringRedisTemplate redis;
    private final GatewayProperties.Ipguard config;

    public RedisIpReputationService(ReactiveStringRedisTemplate redis, GatewayProperties properties) {
        this.redis = redis;
        this.config = properties.getIpguard();
    }

    @Override
    public Mono<Boolean> isBlocked(String ip) {
        return redis.hasKey(BLOCK_PREFIX + ip);
    }

    @Override
    public Mono<Boolean> registerStrike(String ip) {
        String strikesKey = STRIKES_PREFIX + ip;
        Duration window = Duration.ofSeconds(config.getStrikeWindowSec());
        Duration blockTtl = Duration.ofSeconds(config.getBlockTtlSec());

        return redis.opsForValue().increment(strikesKey)
                .flatMap(count -> {
                    // Postavi prozorski TTL pri prvom strike-u (INCR sam ne dira TTL).
                    Mono<Boolean> ensureExpire = count == 1
                            ? redis.expire(strikesKey, window)
                            : Mono.just(true);

                    if (count >= config.getMaxStrikes()) {
                        // SET NX: true samo kad blok-ključ JOŠ ne postoji -> tranzicija u blok.
                        return ensureExpire.then(
                                redis.opsForValue().setIfAbsent(BLOCK_PREFIX + ip, "1", blockTtl));
                    }
                    return ensureExpire.thenReturn(false);
                });
    }
}
