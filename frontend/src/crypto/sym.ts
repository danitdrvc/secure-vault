/**
 * Simetrična enkripcija — AES-256-GCM (autentifikovana).
 *
 * Format šifrata je `nonce (12B) || ciphertext (+16B GCM tag)`, spakovan u jedan
 * `Uint8Array`. Nonce je uvek slučajan po pozivu. Neuspeh autentifikacije pri
 * dekripciji (pogrešan ključ ili izmenjeni bajtovi) baca `CryptoError`.
 */
import { CryptoError } from './errors'
import type { Bytes } from './bytes'

const NONCE_BYTES = 12

/** Uvozi sirove bajtove kao AES-GCM ključ. `extractable` po potrebi (npr. re-wrap USK). */
export function importAesGcmKey(
  raw: Bytes,
  extractable = false,
): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, extractable, [
    'encrypt',
    'decrypt',
  ])
}

/** Šifruje `data`; vraća `nonce || ciphertext`. */
export async function aesGcmEncrypt(
  key: CryptoKey,
  data: Bytes,
): Promise<Bytes> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    data,
  )

  const out = new Uint8Array(nonce.length + ciphertext.byteLength)
  out.set(nonce, 0)
  out.set(new Uint8Array(ciphertext), nonce.length)
  return out
}

/** Dešifruje `nonce || ciphertext`; baca `CryptoError` ako auth tag ne prođe. */
export async function aesGcmDecrypt(
  key: CryptoKey,
  blob: Bytes,
): Promise<Bytes> {
  const nonce = blob.subarray(0, NONCE_BYTES)
  const ciphertext = blob.subarray(NONCE_BYTES)

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      ciphertext,
    )
    return new Uint8Array(plaintext)
  } catch {
    throw new CryptoError(
      'AES-GCM dekripcija nije uspela (pogrešan ključ ili oštećeni podaci).',
    )
  }
}
