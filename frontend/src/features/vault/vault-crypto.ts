/**
 * Čista (bez mreže) kripto-orkestracija vault-a (Faza 6). Sva enkripcija/dekripcija sadržaja
 * tajni dešava se OVDE, na klijentu — server vidi samo base64 šifrat.
 *
 * Envelope model (DEVELOPMENT_PLAN 2.3): svaka tajna ima sopstveni slučajni `secretKey`
 * (AES-256-GCM). Blob = `AES-GCM(secretKey, plaintext)`. `secretKey` se uvija ka javnom ključu
 * korisnika (`RSA-OAEP`) i čuva kao `wrappedSecretKey` — tako se veliki blob nikad ne re-šifruje,
 * a deljenje (Faza 7) samo uvija isti mali `secretKey` ka drugom primaocu.
 */
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  importAesGcmKey,
  unwrap,
  wrapTo,
} from '../../crypto'
import type { Bytes } from '../../crypto'
import { base64ToBytes, bytesToBase64 } from '../../api/codec'

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

/** UTF-8 string → `Bytes` (ArrayBuffer-backed, kako Web Crypto zahteva). */
function utf8(text: string): Bytes {
  return new Uint8Array(textEncoder.encode(text))
}

/** Šifrovani artefakti spremni za `POST /vault/secrets` (oba su base64). */
export interface EncryptedSecret {
  encryptedBlob: string
  wrappedSecretKey: string
}

/**
 * Šifruje novu tajnu: generiše slučajan `secretKey`, šifruje plaintext i uvija `secretKey`
 * ka datom javnom ključu (vlasnikovom). Vraća oba šifrata kao base64.
 */
export async function encryptNewSecret(
  plaintext: string,
  publicKey: CryptoKey,
): Promise<EncryptedSecret> {
  const secretKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ])
  const encryptedBlob = await aesGcmEncrypt(secretKey, utf8(plaintext))
  const secretKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', secretKey))
  const wrappedSecretKey = await wrapTo(publicKey, secretKeyRaw)
  return {
    encryptedBlob: bytesToBase64(encryptedBlob),
    wrappedSecretKey: bytesToBase64(wrappedSecretKey),
  }
}

/**
 * Dešifruje tajnu: privatnim ključem otvori `wrappedSecretKey` → `secretKey`, pa njime
 * dešifruje blob. Pogrešan privatni ključ ili oštećeni podaci → `CryptoError`.
 */
export async function decryptSecret(
  encryptedBlob: string,
  wrappedSecretKey: string,
  privateKey: CryptoKey,
): Promise<string> {
  const secretKeyRaw = await unwrap(privateKey, base64ToBytes(wrappedSecretKey))
  const secretKey = await importAesGcmKey(secretKeyRaw)
  const plaintext = await aesGcmDecrypt(secretKey, base64ToBytes(encryptedBlob))
  return textDecoder.decode(plaintext)
}

/**
 * Ponovo šifruje izmenjeni plaintext ISTIM `secretKey`-em (otvorenim iz postojećeg
 * `wrappedSecretKey`). `wrappedSecretKey` ostaje nepromenjen — zato `PUT` šalje samo blob.
 * Vraća novi `encryptedBlob` (base64).
 */
export async function reencryptSecret(
  plaintext: string,
  wrappedSecretKey: string,
  privateKey: CryptoKey,
): Promise<string> {
  const secretKeyRaw = await unwrap(privateKey, base64ToBytes(wrappedSecretKey))
  const secretKey = await importAesGcmKey(secretKeyRaw)
  const encryptedBlob = await aesGcmEncrypt(secretKey, utf8(plaintext))
  return bytesToBase64(encryptedBlob)
}

/**
 * Deljenje (Faza 7) — envelope re-wrap. Onaj ko deli svojim privatnim ključem otvori
 * `secretKey` iz SVOG `wrappedSecretKey`, pa isti `secretKey` uvije ka javnom ključu
 * PRIMAOCA. Vraća novi `wrappedSecretKey` (base64) koji otvara samo primaočev privatni ključ.
 *
 * `encryptedBlob` se NIKAD ne dira — veliki blob ostaje nepromenjen; deli se samo mali
 * uvijeni ključ. Server vidi isključivo šifrat (plaintext `secretKey` ne napušta čitač).
 */
export async function rewrapSecretForRecipient(
  myWrappedSecretKey: string,
  myPrivateKey: CryptoKey,
  recipientPublicKey: CryptoKey,
): Promise<string> {
  const secretKeyRaw = await unwrap(myPrivateKey, base64ToBytes(myWrappedSecretKey))
  const wrappedForRecipient = await wrapTo(recipientPublicKey, secretKeyRaw)
  return bytesToBase64(wrappedForRecipient)
}
