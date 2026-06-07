package com.securevault.honeypot.service;

import com.securevault.honeypot.domain.SecurityEvent;
import com.securevault.honeypot.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Upis sigurnosnih događaja / alarma u {@code security_event}.
 *
 * <p>Centralna tačka kroz koju svi okidači (IP blok iz Faze 9, honeypot pogodak iz Faze 10,
 * zamrzavanje naloga) beleže alarm. {@code detail} je već-serijalizovan JSON string (kolona je
 * {@code jsonb}); pozivaoci moraju proslediti validan JSON ({@code "{}"} ako nema detalja).
 */
@Service
public class SecurityEventService {

    private final SecurityEventRepository repository;

    public SecurityEventService(SecurityEventRepository repository) {
        this.repository = repository;
    }

    /**
     * Zabeleži događaj.
     *
     * @param type   tip alarma (npr. {@code IP_BLOCKED}, {@code HONEYPOT_HIT})
     * @param userId vezani korisnik ili {@code null}
     * @param ip     IP adresa izvora ili {@code null}
     * @param detailJson dodatni detalji kao JSON string (ne {@code null}; {@code "{}"} ako prazno)
     */
    @Transactional
    public SecurityEvent record(String type, UUID userId, String ip, String detailJson) {
        SecurityEvent event = new SecurityEvent();
        event.setType(type);
        event.setUserId(userId);
        event.setIp(ip);
        event.setDetail(detailJson == null || detailJson.isBlank() ? "{}" : detailJson);
        return repository.save(event);
    }
}
