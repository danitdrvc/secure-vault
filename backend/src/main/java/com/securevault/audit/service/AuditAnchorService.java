package com.securevault.audit.service;

import com.securevault.audit.domain.AuditAnchor;
import com.securevault.audit.domain.AuditLog;
import com.securevault.audit.repository.AuditAnchorRepository;
import com.securevault.audit.repository.AuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Periodično „sidrenje" vrha audit hash-lanca u NEZAVISNI kanal (Faza 11).
 *
 * <p>Hash-lanac sam po sebi otkriva tihu izmenu zapisa, ali ne i prepisivanje CELOG lanca (napadač
 * sa pristupom bazi može preračunati sve heševe iznova). Anchoring to sprečava: {@code headHash}
 * (vrh u trenutku sidrenja) se šalje van baze (email adminu; alternativno log) i upisuje u
 * {@code audit_anchor}. Kasnija verifikacija poredi sačuvani {@code headHash} sa nezavisnom kopijom
 * — neslaganje znači da je lanac prepisan.
 *
 * <p>Posao se izvršava i automatski ({@link #scheduledAnchor()}, {@code @Scheduled}) i ručno
 * (admin preko {@code POST /admin/audit/anchor}). Idempotentno: ako od poslednjeg sidra nema novih
 * zapisa, ne upisuje se nov red.
 */
@Service
public class AuditAnchorService {

    private static final Logger log = LoggerFactory.getLogger(AuditAnchorService.class);

    private static final String CHANNEL_EMAIL = "email";
    private static final String CHANNEL_LOG = "log";

    private final AuditLogRepository auditLogRepository;
    private final AuditAnchorRepository auditAnchorRepository;
    private final JavaMailSender mailSender;

    @Value("${app.alert.admin-email:}")
    private String adminEmail;

    public AuditAnchorService(AuditLogRepository auditLogRepository,
                              AuditAnchorRepository auditAnchorRepository,
                              Optional<JavaMailSender> mailSender) {
        this.auditLogRepository = auditLogRepository;
        this.auditAnchorRepository = auditAnchorRepository;
        this.mailSender = mailSender.orElse(null);
    }

    /**
     * Zakazano sidrenje. Period i početno kašnjenje su konfigurabilni ({@code app.audit.*}); podrazumevano
     * dovoljno veliki da posao ne okine tokom kratkih test JVM-ova (testovi zovu {@link #anchorHead()} direktno).
     */
    @Scheduled(
            initialDelayString = "${app.audit.anchor-initial-delay-ms:3600000}",
            fixedDelayString = "${app.audit.anchor-interval-ms:3600000}")
    public void scheduledAnchor() {
        try {
            anchorHead().ifPresent(a ->
                    log.info("Audit lanac sidren: seq {}..{}, headHash={}, kanal={}",
                            a.getFromSeq(), a.getToSeq(), a.getHeadHash(), a.getChannel()));
        } catch (Exception e) {
            // Sidrenje ne sme da obori aplikaciju; greška se loguje i pokušava se ponovo u sledećem ciklusu.
            log.error("Sidrenje audit lanca nije uspelo: {}", e.getMessage());
        }
    }

    /**
     * Sidri trenutni vrh lanca: šalje {@code headHash} na nezavisni kanal i upisuje
     * {@code audit_anchor} red ({@code from_seq..to_seq}, {@code head_hash}, {@code channel}).
     *
     * @return upisani anchor, ili {@code Optional.empty()} ako nema zapisa za sidrenje
     *         (prazan lanac ili nema novih zapisa od poslednjeg sidra)
     */
    @Transactional
    public Optional<AuditAnchor> anchorHead() {
        Optional<AuditLog> headOpt = auditLogRepository.findTopByOrderBySeqDesc();
        if (headOpt.isEmpty()) {
            return Optional.empty();
        }
        AuditLog head = headOpt.get();
        long toSeq = head.getSeq();
        long fromSeq = auditAnchorRepository.findTopByOrderByToSeqDesc()
                .map(a -> a.getToSeq() + 1)
                .orElse(1L);
        if (fromSeq > toSeq) {
            return Optional.empty(); // nema novih zapisa od poslednjeg sidrenja
        }

        String externalRef = sendToChannel(head.getHash(), fromSeq, toSeq);
        String channel = (externalRef != null) ? CHANNEL_EMAIL : CHANNEL_LOG;

        AuditAnchor anchor = new AuditAnchor();
        anchor.setFromSeq(fromSeq);
        anchor.setToSeq(toSeq);
        anchor.setHeadHash(head.getHash());
        anchor.setChannel(channel);
        anchor.setExternalRef(externalRef);
        return Optional.of(auditAnchorRepository.save(anchor));
    }

    /**
     * Šalje {@code headHash} na nezavisni kanal: email adminu ako je mail konfigurisan, inače WARN log
     * (uvek). Vraća referencu kanala (email adresu) na uspeh email-a, ili {@code null} kada se sidri samo u log.
     */
    private String sendToChannel(String headHash, long fromSeq, long toSeq) {
        // Uvek ostavi trag u logu (nezavisan kanal i kada email nije konfigurisan).
        log.warn("[AUDIT ANCHOR] seq {}..{} headHash={}", fromSeq, toSeq, headHash);

        if (mailSender == null || adminEmail == null || adminEmail.isBlank()) {
            return null;
        }
        try {
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setTo(adminEmail);
            msg.setSubject("[AUDIT ANCHOR] Secure Vault — vrh audit lanca");
            msg.setText(String.format(
                    "Sidrenje audit hash-lanca (Secure Vault).%n%n" +
                    "Opseg zapisa : seq %d..%d%n" +
                    "Head hash    : %s%n%n" +
                    "Sačuvajte ovu vrednost van baze. Pri verifikaciji integriteta uporedite je sa%n" +
                    "trenutnim vrhom lanca — neslaganje ukazuje na prepisivanje audit loga.",
                    fromSeq, toSeq, headHash));
            mailSender.send(msg);
            log.info("Audit anchor email poslat na {}", adminEmail);
            return adminEmail;
        } catch (Exception e) {
            log.error("Slanje audit anchor email-a na {} nije uspelo: {}", adminEmail, e.getMessage());
            return null; // email pao → sidri se kao log kanal (red se i dalje upisuje)
        }
    }
}
