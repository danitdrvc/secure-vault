// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { bootstrapKeys } from '../../crypto'
import { buildRegisterRequest } from './registration'
import { base64ToBytes } from '../../api/codec'

const PW = 'master-lozinka-za-test-123'

describe('buildRegisterRequest', () => {
  it('kodira šifrovane artefakte u base64 očekivanih veličina (poravnato sa backend validacijom)', async () => {
    const { artifacts } = await bootstrapKeys(PW)
    const req = buildRegisterRequest('dev1', 'dev1@securevault.local', artifacts)

    expect(base64ToBytes(req.kdfSalt).length).toBe(16)
    expect(base64ToBytes(req.authKey).length).toBe(32)
    expect(base64ToBytes(req.encUsk).length).toBe(60)
    expect(base64ToBytes(req.publicKey).length).toBe(294)

    const encPrivLen = base64ToBytes(req.encPrivateKey).length
    expect(encPrivLen).toBeGreaterThanOrEqual(1230)
    expect(encPrivLen).toBeLessThanOrEqual(1300)

    expect(req.kdfIterations).toBe(600_000)
    expect(req.username).toBe('dev1')
    expect(req.email).toBe('dev1@securevault.local')
  })

  it('telo registracije NE sadrži master lozinku (zero-knowledge)', async () => {
    const { artifacts } = await bootstrapKeys(PW)
    const req = buildRegisterRequest('dev2', 'dev2@securevault.local', artifacts)

    const serialized = JSON.stringify(req)
    expect(serialized.includes(PW)).toBe(false)
  })
})
