/**
 * Klijentski kripto sloj (zona od poverenja za zero-knowledge).
 *
 * Jedini kripto primitivi dolaze iz Web Crypto API-ja (`crypto.subtle`).
 * Ovaj modul NIKAD ne dodiruje mrežu — radi isključivo u memoriji čitača.
 */
export { CryptoError } from './errors'
export { deriveMasterKey } from './kdf'
export { deriveKek, deriveAuthKey } from './derive'
export { aesGcmEncrypt, aesGcmDecrypt, importAesGcmKey } from './sym'
export {
  generateKeyPair,
  wrapTo,
  unwrap,
  exportPublicKey,
  importPublicKey,
  exportPrivateKey,
  importPrivateKey,
} from './asym'
export { bootstrapKeys, unlock, deriveLoginAuthKey, rotateMasterKey } from './vault'
export type {
  RegistrationArtifacts,
  UnlockedVault,
  VaultKeys,
  BootstrapResult,
  MasterRotationArtifacts,
} from './vault'
export type { Bytes } from './bytes'
