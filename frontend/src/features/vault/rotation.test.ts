import { describe, it, expect } from 'vitest'
import { isRotationDue } from './rotation'

const DAY = 24 * 60 * 60 * 1000
const NOW = new Date('2026-06-07T12:00:00.000Z')

/** ISO string za tajnu rotiranu pre `days` dana u odnosu na NOW. */
function rotatedDaysAgo(days: number): string {
  return new Date(NOW.getTime() - days * DAY).toISOString()
}

describe('isRotationDue (Faza 8)', () => {
  it('istekla tajna (rotated_at + rotation_days u prošlosti) → upozorenje', () => {
    expect(isRotationDue(rotatedDaysAgo(100), 90, NOW)).toBe(true)
  })

  it('još važeća tajna (rok nije prošao) → bez upozorenja', () => {
    expect(isRotationDue(rotatedDaysAgo(10), 90, NOW)).toBe(false)
  })

  it('tačno na granici (rotated_at + rotation_days == sada) → istekla', () => {
    expect(isRotationDue(rotatedDaysAgo(90), 90, NOW)).toBe(true)
  })

  it('rotation_days = null → nikad upozorenje', () => {
    expect(isRotationDue(rotatedDaysAgo(1000), null, NOW)).toBe(false)
  })

  it('rotation_days = 0 ili negativan (nevažeći rok) → bez upozorenja', () => {
    expect(isRotationDue(rotatedDaysAgo(1000), 0, NOW)).toBe(false)
    expect(isRotationDue(rotatedDaysAgo(1000), -5, NOW)).toBe(false)
  })

  it('nevažeći rotatedAt → bez upozorenja (bez bacanja)', () => {
    expect(isRotationDue('not-a-date', 90, NOW)).toBe(false)
  })
})
