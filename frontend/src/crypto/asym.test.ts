// @vitest-environment node
import { describe, it, expect } from 'vitest'
import {
  generateKeyPair,
  wrapTo,
  unwrap,
  exportPublicKey,
  importPublicKey,
} from './asym'
import { CryptoError } from './errors'

describe('RSA-OAEP (asym) — uvijanje za deljenje', () => {
  it('wrapTo(pubB, x) -> unwrap(privB) vraća x', async () => {
    const b = await generateKeyPair()
    const secretKey = crypto.getRandomValues(new Uint8Array(32))

    const box = await wrapTo(b.publicKey, secretKey)
    const out = await unwrap(b.privateKey, box)

    expect(out).toEqual(secretKey)
  })

  it('privatni ključ A NE može da otvori box namenjen B', async () => {
    const a = await generateKeyPair()
    const b = await generateKeyPair()
    const secretKey = crypto.getRandomValues(new Uint8Array(32))

    const box = await wrapTo(b.publicKey, secretKey)

    await expect(unwrap(a.privateKey, box)).rejects.toBeInstanceOf(CryptoError)
  })

  it('javni ključ preživi SPKI export/import (round-trip)', async () => {
    const b = await generateKeyPair()
    const secretKey = crypto.getRandomValues(new Uint8Array(32))

    const spki = await exportPublicKey(b.publicKey)
    const reimported = await importPublicKey(spki)

    const box = await wrapTo(reimported, secretKey)
    expect(await unwrap(b.privateKey, box)).toEqual(secretKey)
  })
})
