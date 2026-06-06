/**
 * Sastavljanje tela registracije iz kripto artefakata.
 *
 * Čista funkcija (bez mreže, bez lozinke u izlazu): uzima šifrovane artefakte koje je
 * `bootstrapKeys` već proizveo i kodira ih u base64 za transport. Master lozinka i
 * izvedeni ključevi (masterKey/KEK/USK/privateKey plaintext) NIKAD ne ulaze u rezultat.
 */
import type { RegistrationArtifacts } from '../../crypto'
import { bytesToBase64 } from '../../api/codec'
import type { RegisterRequest } from './api'

export function buildRegisterRequest(
  username: string,
  email: string,
  artifacts: RegistrationArtifacts,
): RegisterRequest {
  return {
    username,
    email,
    kdfSalt: bytesToBase64(artifacts.kdfSalt),
    kdfIterations: artifacts.kdfIterations,
    authKey: bytesToBase64(artifacts.authKey),
    encUsk: bytesToBase64(artifacts.encUsk),
    publicKey: bytesToBase64(artifacts.publicKey),
    encPrivateKey: bytesToBase64(artifacts.encPrivateKey),
  }
}
