/**
 * Čista (bez mreže) orkestracija promene master lozinke (Faza 8). Izdvojena iz komponente radi
 * testiranja: iz stare/nove lozinke i vraćenog (šifrovanog) vault materijala sastavlja telo za
 * `POST /auth/rotate-master`.
 *
 * Master lozinke i izvedeni ključevi (KEK/USK/privateKey plaintext) NIKAD ne izlaze odavde ka
 * mreži — serveru idu samo base64 šifrati i dokazi identiteta (`currentAuthKey`/`authKey`).
 */
import { rotateMasterKey } from '../../crypto'
import { base64ToBytes, bytesToBase64 } from '../../api/codec'
import type { RotateMasterRequest, VaultMaterial } from './api'

export async function buildRotateMasterRequest(
  oldPassword: string,
  newPassword: string,
  material: VaultMaterial,
): Promise<RotateMasterRequest> {
  const artifacts = await rotateMasterKey(
    oldPassword,
    newPassword,
    base64ToBytes(material.kdfSalt),
    material.kdfIterations,
    base64ToBytes(material.encUsk),
    base64ToBytes(material.encPrivateKey),
  )
  return {
    currentAuthKey: bytesToBase64(artifacts.currentAuthKey),
    authKey: bytesToBase64(artifacts.authKey),
    kdfSalt: bytesToBase64(artifacts.kdfSalt),
    kdfIterations: artifacts.kdfIterations,
    encUsk: bytesToBase64(artifacts.encUsk),
    encPrivateKey: bytesToBase64(artifacts.encPrivateKey),
  }
}
