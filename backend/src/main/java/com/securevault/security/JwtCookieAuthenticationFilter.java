package com.securevault.security;

import com.securevault.user.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

/**
 * Čita access JWT iz {@code sv_access} HttpOnly kolačića, validira ga i puni
 * {@code SecurityContext}. Ako kolačić nedostaje ili je nevažeći — kontekst ostaje prazan
 * i {@link RestAuthenticationEntryPoint} odbija zaštićene rute sa {@code 401}.
 *
 * <p>Filter NIKAD ne baca grešku zbog nevažećeg tokena; samo ne autentikuje zahtev.
 *
 * <p>NIJE Spring bean — instancira ga {@code SecurityConfig} i dodaje u security lanac. Time
 * se izbegava da ga Boot auto-registruje kao samostalni servlet filter (gde bi ga Spring
 * Security {@code SecurityContextHolderFilter} kasnije pregazio).
 */
public class JwtCookieAuthenticationFilter extends OncePerRequestFilter {

    /** Ime kolačića sa access tokenom. */
    public static final String ACCESS_COOKIE = "sv_access";

    private final JwtService jwtService;

    public JwtCookieAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String token = readAccessCookie(request);
        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            authenticate(token);
        }
        filterChain.doFilter(request, response);
    }

    private void authenticate(String token) {
        try {
            Claims claims = jwtService.parse(token);
            if (!JwtService.TYPE_ACCESS.equals(jwtService.type(claims))) {
                return; // refresh/mfa token ne sme da otključa zaštićene rute
            }
            UUID userId = jwtService.subjectId(claims);
            Role role = Role.valueOf(jwtService.role(claims));
            AuthenticatedUser principal = new AuthenticatedUser(userId, jwtService.username(claims), role);

            var authority = new SimpleGrantedAuthority("ROLE_" + role.name());
            var authentication = new UsernamePasswordAuthenticationToken(principal, null, List.of(authority));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException | IllegalArgumentException ex) {
            // Nevažeći/istekao token → ostaje neautentikovano (entry point vraća 401).
            SecurityContextHolder.clearContext();
        }
    }

    private static String readAccessCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (ACCESS_COOKIE.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
