/**
 * Visok kripto sloj vault-a — sastavlja kdf/derive/sym/asym u dva toka:
 *
 *  - `bootstrapKeys(pw)` — pri registraciji: generiše slučajan USK i RSA par, vraća
 *    SAMO šifrovane artefakte za server (zero-knowledge) + otključane ključeve u memoriji.
 *  - `unlock(pw, ...)` — pri loginu: iz lozinke i artefakata rekonstruiše USK i privatni ključ.
 *
 * Slojevi ključeva (objašnjeni u DEVELOPMENT_PLAN 2.3):
 *   masterKey = PBKDF2(pw, salt)        → HKDF → KEK + authKey
 *   USK       = slučajan AES-256        (nezavisan od lozinke; radni ključ)
 *   encUsk    = AES-GCM(KEK, USK)       (promena lozinke re-šifruje samo ovaj blob)
 *   encPriv   = AES-GCM(USK, privateKey)
 *
 * Server nikad ne vidi: master lozinku, masterKey, KEK, USK (plaintext) ni privatni ključ.
 */
import { deriveMasterKey } from './kdf'
import { deriveKek, deriveAuthKey } from './derive'
import { aesGcmEncrypt, aesGcmDecrypt, importAesGcmKey } from './sym'
import {
  generateKeyPair,
  exportPublicKey,
  exportPrivateKey,
  importPrivateKey,
} from './asym'
import type { Bytes } from './bytes'

const DEFAULT_KDF_ITERATIONS = 600_000
const KDF_SALT_BYTES = 16

/** Šifrovani artefakti koji se šalju serveru pri registraciji (ništa od ovoga server ne može dešifrovati). */
export interface RegistrationArtifacts {
  kdfSalt: Bytes
  kdfIterations: number
  /** Dokaz identiteta; server čuva samo `bcrypt(authKey)`. */
  authKey: Bytes
  /** AES-GCM(KEK, USK). */
  encUsk: Bytes
  /** RSA javni ključ (SPKI, plaintext). */
  publicKey: Bytes
  /** AES-GCM(USK, privateKey PKCS8). */
  encPrivateKey: Bytes
}

/** Otključani ključevi koji žive samo u memoriji čitača. */
export interface UnlockedVault {
  /** Radni ključ (AES-256-GCM); extractable radi re-wrap-a pri promeni lozinke. */
  usk: CryptoKey
  /** Privatni ključ za otvaranje deljenih tajni (RSA-OAEP). */
  privateKey: CryptoKey
}

export interface BootstrapResult {
  /** Za slanje serveru. */
  artifacts: RegistrationArtifacts
  /** Za držanje u memoriji (posle registracije korisnik je već otključan). */
  vault: UnlockedVault & { publicKey: CryptoKey }
}

/**
 * Inicijalizuje sve ključeve za novog korisnika iz master lozinke.
 * Vraća šifrovane artefakte za server i otključane ključeve za memoriju.
 */
export async function bootstrapKeys(password: string): Promise<BootstrapResult> {
  const kdfSalt = crypto.getRandomValues(new Uint8Array(KDF_SALT_BYTES))
  const kdfIterations = DEFAULT_KDF_ITERATIONS

  const masterKey = await deriveMasterKey(password, kdfSalt, kdfIterations)
  const kek = await deriveKek(masterKey)
  const authKey = await deriveAuthKey(masterKey)

  // Radni ključ: slučajan AES-256, nezavisan od lozinke.
  const usk = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ])
  const uskRaw = new Uint8Array(await crypto.subtle.exportKey('raw', usk))
  const encUsk = await aesGcmEncrypt(kek, uskRaw)

  // RSA par za deljenje; privatni ključ se šifruje USK-om pre slanja.
  const keyPair = await generateKeyPair()
  const publicKeySpki = await exportPublicKey(keyPair.publicKey)
  const privateKeyPkcs8 = await exportPrivateKey(keyPair.privateKey)
  const encPrivateKey = await aesGcmEncrypt(usk, privateKeyPkcs8)

  return {
    artifacts: {
      kdfSalt,
      kdfIterations,
      authKey,
      encUsk,
      publicKey: publicKeySpki,
      encPrivateKey,
    },
    vault: { usk, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
  }
}

/**
 * Otključava vault iz lozinke i šifrovanih artefakata.
 *
 * Rekonstruiše KEK iz lozinke, njime dešifruje USK, pa USK-om dešifruje privatni
 * ključ. Pogrešna lozinka → pogrešan KEK → AES-GCM auth pada → `CryptoError`.
 */
export async function unlock(
  password: string,
  kdfSalt: Bytes,
  kdfIterations: number,
  encUsk: Bytes,
  encPrivateKey: Bytes,
): Promise<UnlockedVault> {
  const masterKey = await deriveMasterKey(password, kdfSalt, kdfIterations)
  const kek = await deriveKek(masterKey)

  const uskRaw = await aesGcmDecrypt(kek, encUsk)
  const usk = await importAesGcmKey(uskRaw, true)

  const privateKeyPkcs8 = await aesGcmDecrypt(usk, encPrivateKey)
  const privateKey = await importPrivateKey(privateKeyPkcs8)

  return { usk, privateKey }
}
