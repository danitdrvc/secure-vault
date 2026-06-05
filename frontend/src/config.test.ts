import { describe, it, expect } from 'vitest'
import { gatewayUrl } from './config'

describe('config', () => {
  it('gateway url je definisan i nije prazan', () => {
    expect(gatewayUrl).toBeTruthy()
    expect(gatewayUrl).toMatch(/^https?:\/\//)
  })
})
