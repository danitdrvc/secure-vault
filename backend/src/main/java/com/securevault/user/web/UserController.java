package com.securevault.user.web;

import com.securevault.user.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Korisnički endpointi. Saobraćaj stiže kroz gateway ({@code /api/users/**} → {@code /users/**}).
 */
@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
        return userService.register(request);
    }

    /**
     * Imenik korisnika (Faza 7 — deljenje). Zahteva važeću sesiju; vraća samo neosetljive
     * metapodatke (id, username, role) da bi onaj ko deli tajnu izabrao primaoca iz liste
     * umesto ručnog unosa UUID-a.
     */
    @GetMapping
    public List<UserDirectoryEntry> directory() {
        return userService.listDirectory();
    }

    /**
     * Javni ključ korisnika (Faza 7 — deljenje). Zahteva važeću sesiju; javni ključ je javan
     * pa ga sme dohvatiti svaki autentikovan korisnik da bi uvio {@code secretKey} ka primaocu.
     */
    @GetMapping("/{id}/public-key")
    public PublicKeyResponse publicKey(@PathVariable UUID id) {
        return userService.getPublicKey(id);
    }
}
