package com.securevault.gateway.config;

import com.securevault.gateway.guard.ClientIp;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

/**
 * RedisRateLimiter konfiguracija (Faza 9).
 *
 * <p>{@code RequestRateLimiter} filteri u rutama referenciraju {@code #{@ipKeyResolver}} —
 * ovde definisan {@link KeyResolver} koji limit broji PO IP adresi klijenta (a ne globalno),
 * pa flooding sa jednog izvora ne pogađa legitimne korisnike sa drugih IP-ova.
 */
@Configuration
public class RateLimitConfig {

    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> Mono.just(ClientIp.resolve(exchange));
    }
}
