// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { aesGcmEncrypt, aesGcmDecrypt } from './sym'
import { CryptoError } from './errors'

function randomAesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ])
}

const enc = new TextEncoder()

describe('AES-256-GCM (sym)', () => {
  it('enkripcija -> dekripcija vraća isti plaintext', async () => {
    const key = await randomAesKey()
    const data = enc.encode('poverljiva poruka')

    const blob = await aesGcmEncrypt(key, data)
    const out = await aesGcmDecrypt(key, blob)

    expect(out).toEqual(data)
  })

  it('nonce je slučajan — dva šifrata istog teksta se razlikuju', async () => {
    const key = await randomAesKey()
    const data = enc.encode('poverljiva poruka')

    const a = await aesGcmEncrypt(key, data)
    const b = await aesGcmEncrypt(key, data)

    expect(a).not.toEqual(b)
  })

  it('dekripcija pogrešnim ključem baca CryptoError (auth tag radi)', async () => {
    const key = await randomAesKey()
    const wrongKey = await randomAesKey()
    const blob = await aesGcmEncrypt(key, enc.encode('x'))

    await expect(aesGcmDecrypt(wrongKey, blob)).rejects.toBeInstanceOf(CryptoError)
  })

  it('dekripcija izmenjenog šifrata baca CryptoError', async () => {
    const key = await randomAesKey()
    const blob = await aesGcmEncrypt(key, enc.encode('x'))
    blob[blob.length - 1] ^= 0xff // pokvari poslednji bajt (GCM tag)

    await expect(aesGcmDecrypt(key, blob)).rejects.toBeInstanceOf(CryptoError)
  })
})
