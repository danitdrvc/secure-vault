/**
 * Asimetrična kriptografija za deljenje — RSA-OAEP 2048 (SHA-256).
 *
 * Koristi se isključivo za "uvijanje" malog `secretKey` (32B) ka javnom ključu
 * primaoca: `wrapTo(publicKey, ...)` enkriptuje, `unwrap(privateKey, ...)`
 * dekriptuje. Veliki blob tajne se time nikad ne re-šifruje (envelope model).
 */
import { CryptoError } from './errors'
import type { Bytes } from './bytes'

const RSA_PARAMS: RsaHashedKeyGenParams = {
  name: 'RSA-OAEP',
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
  hash: 'SHA-256',
}

const RSA_IMPORT_PARAMS: RsaHashedImportParams = {
  name: 'RSA-OAEP',
  hash: 'SHA-256',
}

/** Generiše RSA-OAEP 2048 par. Privatni ključ je extractable da bi se mogao šifrovati USK-om. */
export function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(RSA_PARAMS, true, ['encrypt', 'decrypt'])
}

/** Enkriptuje `data` ka javnom ključu primaoca. */
export async function wrapTo(
  publicKey: CryptoKey,
  data: Bytes,
): Promise<Bytes> {
  const box = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data)
  return new Uint8Array(box)
}

/** Dekriptuje `box` privatnim ključem; baca `CryptoError` ako ključ ne odgovara. */
export async function unwrap(
  privateKey: CryptoKey,
  box: Bytes,
): Promise<Bytes> {
  try {
    const data = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      box,
    )
    return new Uint8Array(data)
  } catch {
    throw new CryptoError(
      'RSA-OAEP dekripcija nije uspela (pogrešan privatni ključ ili oštećeni podaci).',
    )
  }
}

/** Izvozi javni ključ u SPKI (plaintext format koji server skladišti). */
export async function exportPublicKey(publicKey: CryptoKey): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.exportKey('spki', publicKey))
}

/** Uvozi javni ključ iz SPKI; usage `encrypt` (za uvijanje ka primaocu). */
export function importPublicKey(spki: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey('spki', spki, RSA_IMPORT_PARAMS, true, [
    'encrypt',
  ])
}

/** Izvozi privatni ključ u PKCS8 (radi šifrovanja USK-om pre slanja na server). */
export async function exportPrivateKey(
  privateKey: CryptoKey,
): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey))
}

/** Uvozi privatni ključ iz PKCS8; po default-u non-extractable (živi samo u memoriji). */
export function importPrivateKey(
  pkcs8: Bytes,
  extractable = false,
): Promise<CryptoKey> {
  return crypto.subtle.importKey('pkcs8', pkcs8, RSA_IMPORT_PARAMS, extractable, [
    'decrypt',
  ])
}
