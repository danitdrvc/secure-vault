// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { bootstrapKeys } from '../../crypto'
import { bytesToBase64 } from '../../api/codec'
import { computeAuthKey, unlockVault } from './login'
import type { LoginParamsResponse, VaultMaterial } from './api'

const PW = 'master-lozinka-za-test-123'

/** Iz `bootstrapKeys` izlaza sastavi ono što bi server vratio pri loginu (params + vault). */
async function bootstrapAsServerWouldStore() {
  const { artifacts, vault } = await bootstrapKeys(PW)
  const params: LoginParamsResponse = {
    kdfSalt: bytesToBase64(artifacts.kdfSalt),
    kdfIterations: artifacts.kdfIterations,
  }
  const material: VaultMaterial = {
    kdfSalt: bytesToBase64(artifacts.kdfSalt),
    kdfIterations: artifacts.kdfIterations,
    encUsk: bytesToBase64(artifacts.encUsk),
    publicKey: bytesToBase64(artifacts.publicKey),
    encPrivateKey: bytesToBase64(artifacts.encPrivateKey),
  }
  return { artifacts, vault, params, material }
}

describe('login kripto tok', () => {
  it('computeAuthKey reprodukuje ISTI authKey koji je server upamtio pri registraciji', async () => {
    const { artifacts, params } = await bootstrapAsServerWouldStore()

    const authKey = await computeAuthKey(PW, params)

    // Identičan authKey → bcrypt(authKey) na serveru se poklapa pri loginu.
    expect(authKey).toBe(bytesToBase64(artifacts.authKey))
  })

  it('unlockVault rekonstruiše ISTI USK iz vraćenog vault materijala (round-trip)', async () => {
    const { vault, material } = await bootstrapAsServerWouldStore()

    const unlocked = await unlockVault(PW, material)

    const unlockedUsk = new Uint8Array(await crypto.subtle.exportKey('raw', unlocked.usk))
    const bootstrapUsk = new Uint8Array(await crypto.subtle.exportKey('raw', vault.usk))
    expect(unlockedUsk).toEqual(bootstrapUsk)
  })

  it('pogrešna lozinka NE otključava vault (AES-GCM auth pada)', async () => {
    const { material } = await bootstrapAsServerWouldStore()

    await expect(unlockVault('pogresna-lozinka', material)).rejects.toThrow()
  })
})
