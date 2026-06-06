package com.securevault.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Konfiguracija sigurnosnih bean-ova.
 *
 * <p>U Fazi 3 obezbeđuje samo {@link PasswordEncoder} (bcrypt) za hash-ovanje auth
 * materijala koji klijent šalje ({@code bcrypt(authKey)}). Server NIKAD ne vidi master
 * lozinku — samo izvedeni {@code authKey}, i čuva njegov bcrypt heš. Pun Spring Security
 * filter chain (autentikacija, autorizacija po ulogama, sesije) dolazi u Fazi 4.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
