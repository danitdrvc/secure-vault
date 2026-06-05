package com.securevault.health;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Liveness endpoint. Backend nije izložen spolja (gateway proxy-uje /api/** ka njemu),
 * pa ovaj endpoint služi za interni health-check i za gateway proxy verifikaciju.
 */
@RestController
public class HealthController {

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }
}
