package com.securevault.user.service;

import com.securevault.audit.service.AuditService;
import com.securevault.common.error.ConflictException;
import com.securevault.common.error.NotFoundException;
import com.securevault.common.error.ValidationException;
import com.securevault.user.domain.Role;
import com.securevault.user.domain.User;
import com.securevault.user.domain.UserStatus;
import com.securevault.user.repository.UserRepository;
import com.securevault.user.web.AdminUserResponse;
import com.securevault.user.web.PublicKeyResponse;
import com.securevault.user.web.RegisterRequest;
import com.securevault.user.web.RegisterResponse;
import com.securevault.user.web.UserDirectoryEntry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Poslovna logika korisničkog modula.
 *
 * <p>Registracija je zero-knowledge: server prima samo šifrovane artefakte i izvedeni
 * {@code authKey}, a u bazu upisuje {@code bcrypt(authKey)} (nikad sam authKey ni master
 * lozinku). Kripto blobovi ({@code encUsk}, {@code encPrivateKey}, {@code publicKey}) se
 * skladište kao neprozirni bajtovi — server ih ne može dešifrovati.
 */
@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       AuditService auditService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new ConflictException("Korisničko ime je već zauzeto.");
        }
        if (userRepository.existsByEmail(request.email())) {
            throw new ConflictException("Email je već registrovan.");
        }

        Base64.Decoder decoder = Base64.getDecoder();

        User user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setRole(Role.DEVELOPER);
        user.setStatus(UserStatus.ACTIVE);
        user.setKdfSalt(decoder.decode(request.kdfSalt()));
        user.setKdfIterations(request.kdfIterations());
        // Server čuva SAMO bcrypt(authKey) (authKey je već base64 string sa klijenta).
        // Tako curenje baze ne otkriva login-kredencijal niti bilo šta o master lozinki.
        user.setAuthHash(passwordEncoder.encode(request.authKey()));
        user.setEncUsk(decoder.decode(request.encUsk()));
        user.setPublicKey(decoder.decode(request.publicKey()));
        user.setEncPrivateKey(decoder.decode(request.encPrivateKey()));
        user.setTotpEnabled(false);

        User saved = userRepository.save(user);

        auditService.append("USER_REGISTERED", saved.getId(), "users/" + saved.getId(), "{}");

        return new RegisterResponse(
                saved.getId(),
                saved.getUsername(),
                saved.getEmail(),
                saved.getRole(),
                saved.getStatus());
    }

    /**
     * Imenik korisnika za deljenje (Faza 7). Onaj ko deli tajnu bira primaoca iz liste umesto
     * ručnog unosa UUID-a. Vraća samo neosetljive metapodatke (id, username, role) — nikad
     * email, status ni kripto materijal.
     */
    @Transactional(readOnly = true)
    public List<UserDirectoryEntry> listDirectory() {
        return userRepository.findAllByOrderByUsernameAsc().stream()
                .map(UserDirectoryEntry::from)
                .toList();
    }

    /**
     * Pun pregled svih naloga za admina (Faza 8). Admin tako vidi sve naloge i njihov status
     * umesto da ručno pamti/unosi UUID. Vraća samo neosetljive metapodatke (bez kripto materijala).
     */
    @Transactional(readOnly = true)
    public List<AdminUserResponse> listAllUsers() {
        return userRepository.findAllByOrderByUsernameAsc().stream()
                .map(AdminUserResponse::from)
                .toList();
    }

    /**
     * Javni ključ korisnika za deljenje (Faza 7). Onaj ko deli tajnu njime uvija {@code secretKey}
     * ka primaocu. Vraća samo SPKI javni ključ — nikad privatni materijal.
     */
    @Transactional(readOnly = true)
    public PublicKeyResponse getPublicKey(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("Korisnik ne postoji."));
        return PublicKeyResponse.from(user);
    }

    /**
     * Admin aktivira/deaktivira nalog (Faza 8). Dozvoljene ciljne vrednosti su SAMO
     * {@code ACTIVE} i {@code DEACTIVATED} — {@code FROZEN} je rezervisan za honeypot okidač
     * (Faza 10) i ne postavlja se ručno. {@code ACTIVE} ujedno odmrzava zamrznut nalog
     * (admin reaktivacija). Deaktivacija odmah zaustavlja login (provera u {@code step1}).
     */
    @Transactional
    public AdminUserResponse updateStatus(UUID adminId, UUID targetId, UserStatus status) {
        if (status != UserStatus.ACTIVE && status != UserStatus.DEACTIVATED) {
            throw new ValidationException("Admin može postaviti samo ACTIVE ili DEACTIVATED.");
        }
        User user = userRepository.findById(targetId)
                .orElseThrow(() -> new NotFoundException("Korisnik ne postoji."));

        user.setStatus(status);
        User saved = userRepository.save(user);

        auditService.append("USER_STATUS_CHANGED", adminId, "users/" + targetId,
                "{\"status\":\"" + status.name() + "\"}");
        return AdminUserResponse.from(saved);
    }
}
