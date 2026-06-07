package com.securevault.honeypot.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

/**
 * Alarm adminu kada honeytoken okine (Faza 10).
 *
 * <p>Uvek loguje WARN; šalje email samo ako je {@code spring.mail.host} konfigurisan
 * (Spring Boot auto-konfiguracija kreira {@code JavaMailSender} bean samo tada).
 * U dev/test okruženju bez mail konfiguracije email se preskače bez greške.
 */
@Service
public class AdminAlertService {

    private static final Logger log = LoggerFactory.getLogger(AdminAlertService.class);

    private final JavaMailSender mailSender;

    @Value("${app.alert.admin-email:}")
    private String adminEmail;

    public AdminAlertService(Optional<JavaMailSender> mailSender) {
        this.mailSender = mailSender.orElse(null);
    }

    /**
     * Šalje alarm: WARN log uvek + email ako je mail konfigurisan.
     *
     * @param userId  nalog koji je pristupio honeytoken-u (upravo zamrznut)
     * @param ip      IP adresa poziva ili {@code null}
     */
    public void alertHoneypotHit(UUID userId, String ip) {
        log.warn("[SECURITY ALERT] Honeypot triggered — userId={}, ip={}", userId, ip);

        if (mailSender != null && adminEmail != null && !adminEmail.isBlank()) {
            sendEmail(userId, ip);
        }
    }

    private void sendEmail(UUID userId, String ip) {
        try {
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setTo(adminEmail);
            msg.setSubject("[SECURITY ALERT] Honeypot triggered — Secure Vault");
            msg.setText(String.format(
                    "SECURITY ALERT: Honeypot was triggered%n%n" +
                    "User ID : %s%n" +
                    "Source IP: %s%n%n" +
                    "The user account has been automatically FROZEN.%n" +
                    "Please investigate immediately in the security events dashboard.",
                    userId, ip != null ? ip : "unknown"));
            mailSender.send(msg);
            log.info("Admin alert email sent to {}", adminEmail);
        } catch (Exception e) {
            log.error("Failed to send admin alert email to {}: {}", adminEmail, e.getMessage());
        }
    }
}
