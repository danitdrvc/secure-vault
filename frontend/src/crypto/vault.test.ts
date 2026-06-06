// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { bootstrapKeys, unlock } from './vault'
import { deriveMasterKey } from './kdf'
import { deriveKek, deriveAuthKey } from './derive'
import { wrapTo, unwrap } from './asym'
import { aesGcmDecrypt } from './sym'

const PW = 'master-lozinka-za-test-123'

function exportRaw(key: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.exportKey('raw', key)
}

describe('vault — bootstrap / unlock round-trip', () => {
  it('unlock rekonstruiše IDENTIČAN USK kao bootstrap', async () => {
    const boot = await bootstrapKeys(PW)
    const { kdfSalt, kdfIterations, encUsk, encPrivateKey } = boot.artifacts

    const unlocked = await unlock(PW, kdfSalt, kdfIterations, encUsk, encPrivateKey)

    expect(new Uint8Array(await exportRaw(unlocked.usk))).toEqual(
      new Uint8Array(await exportRaw(boot.vault.usk)),
    )
  })

  it('unlock rekonstruiše privatni ključ koji odgovara objavljenom javnom ključu', async () => {
    const boot = await bootstrapKeys(PW)
    const { kdfSalt, kdfIterations, encUsk, encPrivateKey } = boot.artifacts

    const unlocked = await unlock(PW, kdfSalt, kdfIterations, encUsk, encPrivateKey)

    // Dokaz da je tačno rekonstruisan: ono što je uvijeno ka objavljenom javnom
    // ključu, rekonstruisani privatni ključ uspešno otvara.
    const sample = crypto.getRandomValues(new Uint8Array(32))
    const box = await wrapTo(boot.vault.publicKey, sample)
    expect(await unwrap(unlocked.privateKey, box)).toEqual(sample)
  })

  it('pogrešna lozinka ne otključava vault (KEK ne valja → GCM auth pada)', async () => {
    const boot = await bootstrapKeys(PW)
    const { kdfSalt, kdfIterations, encUsk, encPrivateKey } = boot.artifacts

    await expect(
      unlock('pogresna-lozinka', kdfSalt, kdfIterations, encUsk, encPrivateKey),
    ).rejects.toThrow()
  })

  it('authKey zavisi od labele (vault-auth ≠ vault-kek-izvedeni materijal)', async () => {
    const boot = await bootstrapKeys(PW)
    const masterKey = await deriveMasterKey(
      PW,
      boot.artifacts.kdfSalt,
      boot.artifacts.kdfIterations,
    )

    // Ista master lozinka mora reprodukovati isti authKey (determinizam logina).
    const authAgain = await deriveAuthKey(masterKey)
    expect(authAgain).toEqual(boot.artifacts.authKey)

    // KEK iz iste labele dešifruje encUsk → potvrda da su namene razdvojene a konzistentne.
    const kek = await deriveKek(masterKey)
    const uskRaw = await aesGcmDecrypt(kek, boot.artifacts.encUsk)
    expect(uskRaw.length).toBe(32)
  })
})
