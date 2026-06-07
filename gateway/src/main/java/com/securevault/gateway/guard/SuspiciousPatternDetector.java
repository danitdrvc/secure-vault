package com.securevault.gateway.guard;

import org.springframework.stereotype.Component;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Detekcija sumnjivih sekvenci unosa (SQLi / payload uzorci) u URI putanji i query stringu
 * (Faza 9). Čista logika bez stanja — laka za jedinično testiranje.
 *
 * <p>Cilj nije WAF-grade pokrivenost već prepoznavanje OČIGLEDNIH napadačkih uzoraka
 * (klasičan SQL injection, path traversal, ubacivanje skripte) da bi IpGuardFilter mogao da
 * podigne "strike" i na kraju blokira izvor. Ulaz se prvo URL-dekodira (napadač često koduje
 * payload), pa poredi case-insensitive.
 */
@Component
public class SuspiciousPatternDetector {

    private static final List<Pattern> PATTERNS = List.of(
            // Klasičan SQLi: ' or 1=1, " or 1=1, or '1'='1
            Pattern.compile("(?i)(['\"]?\\s*or\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+)"),
            // SQL ključne reči u kombinaciji koja ne pripada legitimnom API-ju
            Pattern.compile("(?i)\\bunion\\b\\s+\\bselect\\b"),
            Pattern.compile("(?i)\\b(select|insert|update|delete|drop|alter|create)\\b\\s+\\b(from|into|table|database)\\b"),
            // SQL komentar / terminator sekvence
            Pattern.compile("(--|#|/\\*|\\*/|;)\\s*(drop|select|update|delete|insert|union)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)\\b(sleep|benchmark|pg_sleep|waitfor\\s+delay)\\s*\\("),
            // Path traversal
            Pattern.compile("\\.\\./|\\.\\.\\\\"),
            // XSS / script injection
            Pattern.compile("(?i)<\\s*script\\b|javascript:|onerror\\s*=")
    );

    /**
     * @param rawPathAndQuery sirov URI sa query stringom (npr. {@code /api/vault/secrets?q=...})
     * @return {@code true} ako se prepozna sumnjiv uzorak
     */
    public boolean isSuspicious(String rawPathAndQuery) {
        if (rawPathAndQuery == null || rawPathAndQuery.isBlank()) {
            return false;
        }
        String decoded = decode(rawPathAndQuery);
        // Proveri i sirov i dekodiran oblik — payload može biti delom kodovan.
        for (Pattern pattern : PATTERNS) {
            if (pattern.matcher(decoded).find() || pattern.matcher(rawPathAndQuery).find()) {
                return true;
            }
        }
        return false;
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            // Neispravan procenat-enkoding je sam po sebi sumnjiv; vrati original na poređenje.
            return value;
        }
    }
}
