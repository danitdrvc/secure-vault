package com.securevault.honeypot.web;

import java.util.UUID;

/** Jedan pogodak iz ranjivog SQL upita (Faza 10 — demo SQLi endpoint). */
public record HoneytokenSearchResult(UUID id, String label) {}
