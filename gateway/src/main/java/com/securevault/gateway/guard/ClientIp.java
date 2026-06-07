package com.securevault.gateway.guard;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetSocketAddress;

/**
 * Razrešavanje klijentske IP adrese iz zahteva — zajednička tačka za {@code ipKeyResolver}
 * (RedisRateLimiter ključ) i {@link IpGuardFilter}.
 *
 * <p>Prvo gleda {@code X-Forwarded-For} (prvi član lanca = originalni klijent), zatim
 * {@code X-Real-IP}, pa kao fallback {@code remoteAddress}. Tako oba mehanizma broje po
 * ISTOM identitetu izvora.
 */
public final class ClientIp {

    private ClientIp() {
    }

    public static String resolve(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();

        String forwarded = request.getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            // "client, proxy1, proxy2" -> prvi je originalni klijent.
            String first = forwarded.split(",")[0].trim();
            if (!first.isBlank()) {
                return first;
            }
        }

        String realIp = request.getHeaders().getFirst("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }

        InetSocketAddress remote = request.getRemoteAddress();
        if (remote != null && remote.getAddress() != null) {
            return remote.getAddress().getHostAddress();
        }
        return "unknown";
    }
}
