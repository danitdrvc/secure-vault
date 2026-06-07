package com.securevault.config;

import com.securevault.security.JwtCookieAuthenticationFilter;
import com.securevault.security.JwtService;
import com.securevault.security.RestAuthenticationEntryPoint;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
 */
@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties({AuthProperties.class, OidcProperties.class})
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
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/health", "/users/register").permitAll()
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
