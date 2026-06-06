/**
 * Čiste (bez mreže) kripto-orkestracije login toka. Izdvojene iz komponente radi testiranja:
 *  - `computeAuthKey` — iz master lozinke i KDF parametara izvodi base64 `authKey` za step1.
 *  - `unlockVault`    — iz vraćenog vault materijala (step2) rekonstruiše ključeve u memoriji.
 *
 * Master lozinka i izvedeni ključevi (KEK/USK/privateKey plaintext) NIKAD ne izlaze odavde
 * ka mreži — `authKey` je jedino što ide serveru, i to kao dokaz identiteta (server čuva bcrypt).
 */
import { deriveLoginAuthKey, unlock } from '../../crypto'
import type { UnlockedVault } from '../../crypto'
import { base64ToBytes, bytesToBase64 } from '../../api/codec'
import type { LoginParamsResponse, VaultMaterial } from './api'

export async function computeAuthKey(
  password: string,
  params: LoginParamsResponse,
): Promise<string> {
  const authKey = await deriveLoginAuthKey(
    password,
    base64ToBytes(params.kdfSalt),
    params.kdfIterations,
  )
  return bytesToBase64(authKey)
}

export async function unlockVault(
  password: string,
  vault: VaultMaterial,
): Promise<UnlockedVault> {
  return unlock(
    password,
    base64ToBytes(vault.kdfSalt),
    vault.kdfIterations,
    base64ToBytes(vault.encUsk),
    base64ToBytes(vault.encPrivateKey),
  )
}
