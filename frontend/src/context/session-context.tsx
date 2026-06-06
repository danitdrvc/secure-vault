/**
 * Sesijsko stanje koje živi ISKLJUČIVO u memoriji (React state) — nikad u localStorage /
 * sessionStorage. Drži prijavljenog korisnika i otključani vault (`usk` + privatni ključ).
 *
 * Posledica (po dizajnu, DEVELOPMENT_PLAN 2.3): refresh stranice briše ključeve iz memorije
 * → potrebno je ponovno otključavanje (unos master lozinke). Tako se izbegava perzistencija
 * osetljivog kripto materijala van zone od poverenja.
 */
import { createContext, useContext, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import type { UnlockedVault } from '../crypto'
import type { AuthUser } from '../features/auth/api'

interface SessionContextValue {
  user: AuthUser | null
  /** Otključani ključevi (samo u memoriji); `null` dok vault nije otključan. */
  vault: UnlockedVault | null
  isUnlocked: boolean
  /** Postavlja sesiju posle uspešnog logina + otključavanja. */
  setSession: (user: AuthUser, vault: UnlockedVault) => void
  /** Briše ključeve i korisnika iz memorije (odjava / zaključavanje). */
  clear: () => void
}

const SessionContext = createContext<SessionContextValue | null>(null)

export function SessionProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [vault, setVault] = useState<UnlockedVault | null>(null)

  const value = useMemo<SessionContextValue>(
    () => ({
      user,
      vault,
      isUnlocked: vault !== null,
      setSession: (nextUser, nextVault) => {
        setUser(nextUser)
        setVault(nextVault)
      },
      clear: () => {
        setUser(null)
        setVault(null)
      },
    }),
    [user, vault],
  )

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}

export function useSession(): SessionContextValue {
  const ctx = useContext(SessionContext)
  if (!ctx) {
    throw new Error('useSession mora biti unutar <SessionProvider>')
  }
  return ctx
}
