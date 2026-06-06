// @vitest-environment node
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { bootstrapKeys, unlock } from './vault'
import { generateKeyPair, wrapTo, unwrap } from './asym'

/**
 * Negativan test (zero-knowledge invarijanta): kripto sloj NIKAD ne sme da emituje
 * ključeve — niti bilo šta — kroz mrežu. Sve mrežne primitive su zamenjene mock-om
 * koji puca pri pozivu; pun kripto tok mora da prođe ne dodirnuvši nijednu.
 */
describe('kripto sloj ne dodiruje mrežu (nema curenja ključeva)', () => {
  let fetchSpy: ReturnType<typeof vi.fn>
  let originalFetch: typeof globalThis.fetch
  let originalXhr: typeof globalThis.XMLHttpRequest

  beforeEach(() => {
    originalFetch = globalThis.fetch
    originalXhr = globalThis.XMLHttpRequest

    fetchSpy = vi.fn(() => {
      throw new Error('fetch nije dozvoljen u kripto sloju')
    })
    globalThis.fetch = fetchSpy as unknown as typeof globalThis.fetch
    globalThis.XMLHttpRequest = class {
      open(): never {
        throw new Error('XMLHttpRequest nije dozvoljen u kripto sloju')
      }
    } as unknown as typeof globalThis.XMLHttpRequest
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    globalThis.XMLHttpRequest = originalXhr
  })

  it('bootstrapKeys + unlock + wrap/unwrap ne pozivaju mrežu', async () => {
    const boot = await bootstrapKeys('lozinka')
    await unlock(
      'lozinka',
      boot.artifacts.kdfSalt,
      boot.artifacts.kdfIterations,
      boot.artifacts.encUsk,
      boot.artifacts.encPrivateKey,
    )

    const pair = await generateKeyPair()
    const box = await wrapTo(pair.publicKey, boot.artifacts.authKey)
    await unwrap(pair.privateKey, box)

    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
