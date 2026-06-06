// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { bytesToBase64, base64ToBytes } from './codec'

describe('codec base64', () => {
  it('round-trip proizvoljnih bajtova', () => {
    const bytes = crypto.getRandomValues(new Uint8Array(64))
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes)
  })

  it('proizvodi standardni base64 sa paddingom', () => {
    const oneByte = crypto.getRandomValues(new Uint8Array(1))
    expect(bytesToBase64(oneByte)).toMatch(/==$/)
  })

  it('prazni niz → prazan string i nazad', () => {
    const empty = new Uint8Array(0) as Uint8Array<ArrayBuffer>
    expect(bytesToBase64(empty)).toBe('')
    expect(base64ToBytes('')).toEqual(empty)
  })
})
