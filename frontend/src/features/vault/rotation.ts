/**
 * Logika roka rotacije tajne (Faza 8). Čista funkcija (bez mreže, bez kripta).
 *
 * Server je zero-knowledge i ne okida rotaciju automatski — kad vlasnik OTVORI tajnu, klijent
 * poredi `rotatedAt + rotationDays` sa sada i, ako je isteklo, prikazuje upozorenje sa akcijom
 * „Rotiraj sada".
 */

const MS_PER_DAY = 24 * 60 * 60 * 1000

/**
 * Da li je rok rotacije istekao. `rotationDays = null` (bez rotacije), `≤ 0`, ili nevažeći
 * `rotatedAt` → uvek `false` (nema upozorenja). U suprotnom je istekao kad je
 * `rotatedAt + rotationDays` u prošlosti u odnosu na `now`.
 */
export function isRotationDue(
  rotatedAt: string,
  rotationDays: number | null | undefined,
  now: Date = new Date(),
): boolean {
  if (rotationDays == null || rotationDays <= 0) {
    return false
  }
  const rotatedMs = new Date(rotatedAt).getTime()
  if (Number.isNaN(rotatedMs)) {
    return false
  }
  return rotatedMs + rotationDays * MS_PER_DAY <= now.getTime()
}
