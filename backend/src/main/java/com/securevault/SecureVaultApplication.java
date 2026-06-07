package com.securevault;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * {@code @EnableScheduling} pokreće periodični posao sidrenja audit lanca
 * ({@code AuditAnchorService}, Faza 11). Interval/početno kašnjenje su konfigurabilni
 * ({@code app.audit.*}); podrazumevano su dovoljno veliki da posao ne okine tokom testova.
 */
@SpringBootApplication
@EnableScheduling
public class SecureVaultApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureVaultApplication.class, args);
    }
}
