package com.securevault.config;

import com.securevault.security.JwtCookieAuthenticationFilter;
import com.securevault.security.JwtService;
import com.securevault.security.RestAuthenticationEntryPoint;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;

/**
 * Spring Security konfiguracija (Faza 4).
 *
 * <p>Stateless, token-based API: nema server-side sesije; autentikacija se nosi access JWT-om
 * u {@code sv_access} HttpOnly kolačiću ({@link JwtCookieAuthenticationFilter}). CSRF je
 * isključen jer su kolačići {@code SameSite=Strict} (cross-site POST ne nosi kolačić), a API
 * je bez server-side sesijskog stanja.
 *
 * <p>Javne rute (bez tokena): registracija i ceo login tok (params/step1/totp/step2/refresh) —
 * njih štiti bcrypt + TOTP + MFA tiket na nivou servisa. Sve ostalo zahteva važeći access token.
 *
 * <p><b>Faza 12 — hardening:</b> svaki odgovor nosi sigurnosne HTTP zaglavlja
 * ({@code Content-Security-Policy}, {@code X-Frame-Options}, {@code X-Content-Type-Options},
 * {@code Referrer-Policy}, {@code Permissions-Policy}, {@code Strict-Transport-Security}).
 * Backend je API (vraća JSON, ne HTML), pa je CSP maksimalno restriktivan
 * ({@code default-src 'none'}). Ova zaglavlja gateway prosleđuje browseru na {@code /api/**}.
 */
@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties({AuthProperties.class, OidcProperties.class, InternalProperties.class})
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtService jwtService,
                                                   RestAuthenticationEntryPoint entryPoint) throws Exception {
        JwtCookieAuthenticationFilter jwtFilter = new JwtCookieAuthenticationFilter(jwtService);
        http
                .csrf(AbstractHttpConfigurer::disable)
                // CORS rešava gateway (jedina ulazna tačka); backend nije izložen spolja.
                .cors(AbstractHttpConfigurer::disable)
                // Faza 12 — sigurnosna zaglavlja na svakom odgovoru (uklj. 401/403 iz entry point-a).
                .headers(headers -> headers
                        // X-Content-Type-Options: nosniff — bez MIME sniffing-a.
                        .contentTypeOptions(Customizer.withDefaults())
                        // X-Frame-Options: DENY — bez učitavanja u frame (clickjacking zaštita).
                        .frameOptions(frame -> frame.deny())
                        // Referrer-Policy: no-referrer — ne curi URL u Referer zaglavlju.
                        .referrerPolicy(referrer -> referrer
                                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        // CSP: API vraća JSON, ne HTML → ništa se ne sme učitati ni ugraditi.
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"))
                        // HSTS — primenjuje se samo preko HTTPS-a (u dev-u nad http se ne emituje).
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000))
                        // Permissions-Policy — onemogući moćne browser API-je za ovaj origin.
                        .addHeaderWriter(new StaticHeadersWriter("Permissions-Policy",
                                "geolocation=(), microphone=(), camera=(), payment=(), usb=()")))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/health", "/users/register").permitAll()
                        // Interne (server-to-server) rute: nisu izložene kroz gateway, a štiti ih
                        // deljeni X-Internal-Token koji proverava sam kontroler.
                        .requestMatchers("/internal/**").permitAll()
                        .requestMatchers("/auth/login/**", "/auth/totp/**", "/auth/refresh").permitAll()
                        // OIDC redirect tok (start/callback) je javan — štite ga state/nonce + verifikacija id_token-a.
                        .requestMatchers("/auth/oidc/**").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(entryPoint))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
