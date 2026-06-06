// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { bootstrapKeys } from '../../crypto'
import { bytesToBase64 } from '../../api/codec'
import { unlockVault } from './login'
import { oidcStartUrl } from './api'
import type { VaultMaterial } from './api'

describe('OIDC prijava (Faza 5)', () => {
  it('oidcStartUrl gađa gateway /api/auth/oidc/start (full-page redirect, ne XHR)', () => {
    expect(oidcStartUrl()).toBe('http://localhost:8080/api/auth/oidc/start')
  })

  it('posle OIDC-a vault je zaključan dok master lozinka ne otključa šifrovani materijal', async () => {
    const PW = 'master-lozinka-za-test-123'
    const { artifacts, vault } = await bootstrapKeys(PW)
    // Materijal koji klijent dohvati sa /auth/vault-material posle OIDC sesije (samo šifrat).
    const material: VaultMaterial = {
      kdfSalt: bytesToBase64(artifacts.kdfSalt),
      kdfIterations: artifacts.kdfIterations,
      encUsk: bytesToBase64(artifacts.encUsk),
      publicKey: bytesToBase64(artifacts.publicKey),
      encPrivateKey: bytesToBase64(artifacts.encPrivateKey),
    }

    // Bez (tačne) master lozinke materijal je beskoristan — OIDC sesija ga ne otključava.
    await expect(unlockVault('pogresna-lozinka', material)).rejects.toThrow()

    // Sa master lozinkom klijent rekonstruiše ISTI USK lokalno.
    const unlocked = await unlockVault(PW, material)
    const unlockedUsk = new Uint8Array(await crypto.subtle.exportKey('raw', unlocked.usk))
    const bootstrapUsk = new Uint8Array(await crypto.subtle.exportKey('raw', vault.usk))
    expect(unlockedUsk).toEqual(bootstrapUsk)
  })
})
