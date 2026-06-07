package com.securevault.policy.web;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

/**
 * Telo zahteva za admin izmenu sigurnosne politike ({@code PATCH /admin/policy}).
 *
 * <p>PATCH semantika: sva polja su opciona ({@code null} = ostavi nepromenjeno). Bean Validation
 * granice ({@code @Min}/{@code @Max}) se primenjuju samo kad polje NIJE {@code null}.
 *
 * <p>„Trajanje sesije" se adminu izlaže kao {@code sessionMaxTtlSec} — apsolutni cap od logina
 * posle kojeg sledi obavezan ponovni login. {@code accessTokenTtlSec} je zaseban tehnički prozor
 * rotacije, {@code refreshTokenTtlSec} trajanje pojedinačnog refresh tokena (DEVELOPMENT_PLAN 2.3).
 */
public record UpdatePolicyRequest(

        @Min(value = 8, message = "min dužina master lozinke ne sme biti ispod 8")
        @Max(value = 128, message = "min dužina master lozinke je nerealno velika")
        Integer minMasterPwLength,

        @Min(value = 1, message = "default rotation days mora biti pozitivan")
        @Max(value = 3650, message = "default rotation days je nerealno velik")
        Integer defaultRotationDays,

        @Min(value = 30, message = "access token TTL mora biti najmanje 30s")
        @Max(value = 3600, message = "access token TTL je nerealno velik")
        Integer accessTokenTtlSec,

        @Min(value = 60, message = "refresh token TTL mora biti najmanje 60s")
        @Max(value = 604_800, message = "refresh token TTL je nerealno velik")
        Integer refreshTokenTtlSec,

        @Min(value = 60, message = "trajanje sesije mora biti najmanje 60s")
        @Max(value = 604_800, message = "trajanje sesije je nerealno veliko")
        Integer sessionMaxTtlSec,

        Boolean honeypotEndpoint
) {
}
