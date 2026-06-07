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

/**
 * Pun set ključeva u memoriji sesije: otključani vault + sopstveni javni ključ (usage `encrypt`).
 * Javni ključ je potreban da klijent uvije `secretKey` ka SEBI pri kreiranju tajne (Faza 6),
 * bez ponovnog dohvata sa servera.
 */
export interface VaultKeys extends UnlockedVault {
  publicKey: CryptoKey
}

export interface BootstrapResult {
  /** Za slanje serveru. */
  artifacts: RegistrationArtifacts
  /** Za držanje u memoriji (posle registracije korisnik je već otključan). */
  vault: VaultKeys
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
 * Izvodi `authKey` iz master lozinke za login (isti put kao u `bootstrapKeys`:
 * PBKDF2 → HKDF `info="vault-auth"`). Server poredi `bcrypt(authKey)`; master lozinka
 * i KEK NIKAD ne napuštaju čitač.
 */
export async function deriveLoginAuthKey(
  password: string,
  kdfSalt: Bytes,
  kdfIterations: number,
): Promise<Bytes> {
  const masterKey = await deriveMasterKey(password, kdfSalt, kdfIterations)
  return deriveAuthKey(masterKey)
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

/** Re-šifrovani artefakti za {@code POST /auth/rotate-master} (Faza 8). */
export interface MasterRotationArtifacts {
  /** Dokaz STARE lozinke; server ga poredi sa `auth_hash` pre primene izmene. */
  currentAuthKey: Bytes
  /** Novi dokaz identiteta; server čuva samo `bcrypt(authKey)`. */
  authKey: Bytes
  /** Svež PBKDF2 salt (dobra praksa pri promeni lozinke). */
  kdfSalt: Bytes
  kdfIterations: number
  /** AES-GCM(noviKEK, USK) — USK je NEPROMENJEN. */
  encUsk: Bytes
  /** AES-GCM(USK, PKCS8) sa svežim nonce-om. */
  encPrivateKey: Bytes
}

/**
 * Promena master lozinke bez diranja tajni (Faza 8).
 *
 * Otključa stari KEK i USK starom lozinkom, izvede NOV KEK/authKey iz nove lozinke (uz svež
 * salt) i re-šifruje SAMO `encUsk` (pod novim KEK) i `encPrivateKey` (pod ISTIM USK, svež nonce).
 * Pošto USK i privatni ključ ostaju isti, sve postojeće tajne i deljenja rade i sa novom lozinkom.
 *
 * Pogrešna stara lozinka → pogrešan stari KEK → AES-GCM auth pada → `CryptoError`. Master lozinka,
 * KEK i USK (plaintext) NIKAD ne napuštaju čitač.
 */
export async function rotateMasterKey(
  oldPassword: string,
  newPassword: string,
  kdfSalt: Bytes,
  kdfIterations: number,
  encUsk: Bytes,
  encPrivateKey: Bytes,
): Promise<MasterRotationArtifacts> {
  // 1) Otključaj stari KEK i USK; izvedi dokaz stare lozinke.
  const oldMaster = await deriveMasterKey(oldPassword, kdfSalt, kdfIterations)
  const oldKek = await deriveKek(oldMaster)
  const currentAuthKey = await deriveAuthKey(oldMaster)

  const uskRaw = await aesGcmDecrypt(oldKek, encUsk)
  const usk = await importAesGcmKey(uskRaw)
  // Privatni ključ kao bajtovi (nikad kao CryptoKey) — re-šifruje se ISTIM USK sa svežim nonce-om.
  const privateKeyPkcs8 = await aesGcmDecrypt(usk, encPrivateKey)

  // 2) Nova lozinka → svež salt, nov KEK i authKey.
  const newSalt = crypto.getRandomValues(new Uint8Array(KDF_SALT_BYTES))
  const newIterations = DEFAULT_KDF_ITERATIONS
  const newMaster = await deriveMasterKey(newPassword, newSalt, newIterations)
  const newKek = await deriveKek(newMaster)
  const authKey = await deriveAuthKey(newMaster)

  // 3) Re-šifruj USK pod novim KEK; privatni ključ ostaje pod istim USK (svež nonce).
  const newEncUsk = await aesGcmEncrypt(newKek, uskRaw)
  const newEncPrivateKey = await aesGcmEncrypt(usk, privateKeyPkcs8)

  return {
    currentAuthKey,
    authKey,
    kdfSalt: newSalt,
    kdfIterations: newIterations,
    encUsk: newEncUsk,
    encPrivateKey: newEncPrivateKey,
  }
}
