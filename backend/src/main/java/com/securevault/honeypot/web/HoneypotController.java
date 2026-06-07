package com.securevault.honeypot.web;

import com.securevault.common.error.NotFoundException;
import com.securevault.honeypot.service.HoneypotService;
import com.securevault.policy.service.SecurityPolicyService;
import com.securevault.security.AuthenticatedUser;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin-togglable ranjivi endpoint (Faza 10).
 *
 * <p>Dostupan samo kada {@code policy.honeypot_endpoint = true}; inače vraća {@code 404}.
 * Zahteva autentikaciju (nalog pozivača se može zamrznuti ako SQLi dohvati honeytoken).
 *
 * <p><b>NAPOMENA:</b> endpoint je NAMERNO RANJIV na SQL Injection — izolovan, samo za
 * edukativnu demonstraciju. Ne koristiti u produkcijskom okruženju bez admin kontrole.
 */
@RestController
@RequestMapping("/honeypot")
public class HoneypotController {

    private final HoneypotService honeypotService;
    private final SecurityPolicyService policyService;

    public HoneypotController(HoneypotService honeypotService,
                               SecurityPolicyService policyService) {
        this.honeypotService = honeypotService;
        this.policyService = policyService;
    }

    /**
     * Pretraži honeytokene po labeli — ranjivo na SQLi kada je endpoint aktivan.
     *
     * @param label  korisnički unos koji se ugrađuje direktno u SQL (demonstracija SQLi)
     */
    @GetMapping("/search")
    public List<HoneytokenSearchResult> search(
            @AuthenticationPrincipal AuthenticatedUser principal,
            @RequestParam String label,
            HttpServletRequest request) {

        if (!policyService.isHoneypotEndpointEnabled()) {
            throw new NotFoundException("Endpoint nije aktivan.");
        }

        String ip = request.getRemoteAddr();
        return honeypotService.vulnerableSearch(principal.id(), ip, label);
    }
}
