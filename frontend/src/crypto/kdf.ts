/**
 * Derivacija master ključa iz master lozinke (PBKDF2-HMAC-SHA256).
 *
 * Jedini kripto sloj je ugrađeni Web Crypto API (`crypto.subtle`) — bez eksternih
 * biblioteka i bez sopstvenih implementacija algoritama. Master ključ se nikada ne
 * šalje na server; ostaje samo u memoriji čitača.
 */

import type { Bytes } from './bytes'

const encoder = new TextEncoder()

/**
 * Reprodukuje master ključ iz lozinke, soli i broja iteracija.
 *
 * Vraća se kao non-extractable HKDF bazni ključ — namene (KEK / authKey) se iz
 * njega izvode odvojeno u `derive.ts`, bez ikad izloženih sirovih bajtova ovde.
 */
export async function deriveMasterKey(
  password: string,
  salt: Bytes,
  iterations: number,
): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  )

  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    passwordKey,
    256,
  )

  // Uvozi izvedene bitove kao HKDF ulazni materijal (IKM) za razdvajanje namena.
  return crypto.subtle.importKey('raw', bits, 'HKDF', false, [
    'deriveKey',
    'deriveBits',
  ])
}
