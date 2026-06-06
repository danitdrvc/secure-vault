package com.securevault.auth.web;

/**
 * {@code otpauth://} URI (za ručni unos / parsiranje) i PNG QR kao {@code data:} URI
 * (za prikaz u browseru). Tajna se proviziuje samo ovde — server je čuva šifrovanu.
 */
public record TotpSetupResponse(String otpauthUri, String qrDataUri) {
}
