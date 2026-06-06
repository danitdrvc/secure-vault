/**
 * Razdvajanje namena master ključa preko HKDF (HMAC-SHA256).
 *
 * Iz istog master ključa izvode se dva nezavisna materijala odvojenim `info`
 * labelama, tako da poznavanje jednog ne otkriva drugi:
 *  - KEK     (`vault-kek`)  — Key Encryption Key, šifruje/dešifruje USK.
 *  - authKey (`vault-auth`) — dokaz identiteta koji se šalje serveru (server čuva
 *    samo `bcrypt(authKey)`; KEK ostaje na klijentu i server ga nikad ne vidi).
 */

import type { Bytes } from './bytes'

const encoder = new TextEncoder()

const KEK_INFO = encoder.encode('vault-kek')
const AUTH_INFO = encoder.encode('vault-auth')

// HKDF so je opciona (tretira se kao nule); razdvajanje obezbeđuju `info` labele.
const HKDF_SALT = new Uint8Array(0)

/** Izvodi KEK (AES-256-GCM) iz master ključa. Non-extractable — koristi se samo lokalno. */
export async function deriveKek(masterKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: KEK_INFO },
    masterKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

/** Izvodi authKey (32 bajta) koji se šalje serveru kao dokaz identiteta. */
export async function deriveAuthKey(masterKey: CryptoKey): Promise<Bytes> {
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: AUTH_INFO },
    masterKey,
    256,
  )
  return new Uint8Array(bits)
}
