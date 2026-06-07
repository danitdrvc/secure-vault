package com.securevault.honeypot.service;

import com.securevault.audit.service.AuditService;
import com.securevault.honeypot.web.HoneytokenSearchResult;
import com.securevault.user.domain.UserStatus;
import com.securevault.user.repository.UserRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Logika honeypot detekcije (Faza 10).
 *
 * <p>Dve ulazne tačke:
 * <ol>
 *   <li>{@link #triggerHoneypot} — poziva {@code VaultService} kada korisnik pokuša direktan
 *       pristup honeytoken tajni kroz regularni API. Koristi {@code REQUIRES_NEW} jer spoljašnja
 *       transakcija ({@code readOnly}) biva rollback-ovana izuzetkom {@code 404} — zamrzavanje
 *       i event MORAJU biti komitovani bez obzira na to.
 *   <li>{@link #vulnerableSearch} — ranjivi admin-togglable endpoint koji namerno koristi
 *       konkatenaciju stringa u SQL upitu radi demonstracije SQL injection napada.
 * </ol>
 */
@Service
public class HoneypotService {

    private final UserRepository userRepository;
    private final SecurityEventService securityEventService;
    private final AuditService auditService;
    private final AdminAlertService adminAlertService;
    private final JdbcTemplate jdbcTemplate;

    public HoneypotService(UserRepository userRepository,
                           SecurityEventService securityEventService,
                           AuditService auditService,
                           AdminAlertService adminAlertService,
                           JdbcTemplate jdbcTemplate) {
        this.userRepository = userRepository;
        this.securityEventService = securityEventService;
        this.auditService = auditService;
        this.adminAlertService = adminAlertService;
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Okidač kada regularni API detektuje pristup honeytoken tajni.
     *
     * <p>{@code REQUIRES_NEW}: spoljašnja transakcija ({@code VaultService.get}, readOnly) biva
     * rollback-ovana posle {@code NotFoundException} koji sledi — ova transakcija mora komitovati
     * nezavisno kako bi zamrzavanje i {@code security_event} bili trajno sačuvani.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void triggerHoneypot(UUID userId, String ip, UUID secretId) {
        String detail = "{\"secretId\":\"" + secretId + "\"}";
        doFreezeAndRecord(userId, ip, detail);
    }

    /**
     * NAMERNO RANJIV SQL endpoint za demonstraciju SQL Injection-a (Faza 10).
     *
     * <p>Upit se gradi konkatenacijom korisničkog unosa — ovo je NAMERNA RANJIVOST koja
     * postoji isključivo radi edukativne demonstracije. Endpoint je aktivan samo kada admin
     * uključi {@code policy.honeypot_endpoint = true}; inače ga kontroler vraća kao {@code 404}.
     *
     * <p>Kada SQLi payload dohvati honeytoken red, okidač automatski:
     * <ul>
     *   <li>Zamrzava nalog pozivača ({@code FROZEN});
     *   <li>Beleži {@code HONEYPOT_HIT} event;
     *   <li>Šalje alarm adminu.
     * </ul>
     *
     * @param callerId  UUID autentikovanog korisnika koji šalje zahtev
     * @param ip        IP adresa poziva (za event/alarm)
     * @param label     korisnički unos koji se DIREKTNO ugrađuje u SQL (ranjivo!)
     */
    @Transactional
    public List<HoneytokenSearchResult> vulnerableSearch(UUID callerId, String ip, String label) {
        // INTENTIONAL SQL INJECTION VULNERABILITY — demonstration only.
        // Never use string concatenation in production SQL queries.
        @SuppressWarnings("SqlSourceToSinkFlow")
        String sql = "SELECT id, label FROM honeytoken WHERE label = '" + label + "'";

        List<HoneytokenSearchResult> results = jdbcTemplate.query(sql,
                (rs, rowNum) -> new HoneytokenSearchResult(
                        UUID.fromString(rs.getString("id")),
                        rs.getString("label")));

        if (!results.isEmpty()) {
            doFreezeAndRecord(callerId, ip, "{\"sqli\":true}");
        }
        return results;
    }

    private void doFreezeAndRecord(UUID userId, String ip, String detail) {
        userRepository.findById(userId).ifPresent(user -> {
            if (user.getStatus() == UserStatus.ACTIVE) {
                user.setStatus(UserStatus.FROZEN);
                userRepository.save(user);
            }
        });
        securityEventService.record("HONEYPOT_HIT", userId, ip, detail);
        auditService.record("HONEYPOT_TRIGGERED", userId, "honeypot", "{}");
        adminAlertService.alertHoneypotHit(userId, ip);
    }
}
