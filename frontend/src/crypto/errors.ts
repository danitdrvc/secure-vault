/**
 * Tipizovana greška klijentskog kripto sloja.
 *
 * Baca se kada autentifikovana dekripcija (AES-256-GCM ili RSA-OAEP) ne uspe —
 * tipično pogrešan ključ (npr. pogrešna master lozinka) ili oštećeni/izmenjeni
 * šifrat. NIKAD se ne radi "tihi" fallback: neuspeh auth taga je jasna greška.
 */
export class CryptoError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CryptoError'
  }
}
