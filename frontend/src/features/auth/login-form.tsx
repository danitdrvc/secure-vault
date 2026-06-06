import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import axios from 'axios'
import { useSession } from '../../context/session-context'
import { computeAuthKey, unlockVault } from './login'
import {
  fetchLoginParams,
  fetchMe,
  fetchVaultMaterial,
  loginStep1,
  loginStep2,
  oidcStartUrl,
  totpSetup,
  totpVerify,
} from './api'
import type { TotpSetupResponse } from './api'

/** Faze login toka prikazane korisniku. */
type Phase = 'credentials' | 'totp-setup' | 'totp' | 'oidc-unlock' | 'done'
type Status = 'idle' | 'busy' | 'error'

/** Iz axios/greške izvlači poruku iz konzistentnog oblika { error: { message } }. */
function extractError(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const data = err.response?.data as { error?: { message?: string } } | undefined
    if (data?.error?.message) {
      return data.error.message
    }
  }
  if (err instanceof Error) {
    return err.message
  }
  return 'Prijava nije uspela.'
}

/**
 * Login forma (Faza 4): lozinka → TOTP (drugi faktor) → otključavanje vault-a u memoriji.
 *
 * Master lozinka se izvodi lokalno u `authKey` (server vidi samo njega) i čuva u state-u dok
 * traje tok, da bi se posle step2 vault otključao iz vraćenog (šifrovanog) materijala. Ključevi
 * žive samo u `SessionContext` memoriji — nikad u storage-u.
 */
export default function LoginForm() {
  const session = useSession()
  const [searchParams, setSearchParams] = useSearchParams()
  const [phase, setPhase] = useState<Phase>('credentials')
  const [status, setStatus] = useState<Status>('idle')
  const [message, setMessage] = useState('')

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')

  const [mfaTicket, setMfaTicket] = useState('')
  const [setupInfo, setSetupInfo] = useState<TotpSetupResponse | null>(null)

  const busy = status === 'busy'

  // Posle OIDC redirect-a backend vraća na /login?oidc=success|error. Sesija (kolačići) tada
  // postoji, ali vault je JOŠ ZAKLJUČAN — tražimo master lozinku da bismo lokalno otključali
  // (OIDC ne daje ključ; zero-knowledge očuvan). Query param čistimo da refresh ne ponovi tok.
  useEffect(() => {
    const oidc = searchParams.get('oidc')
    if (oidc === 'success') {
      setPhase('oidc-unlock')
      setMessage('Eksterna prijava uspešna. Unesite master lozinku da otključate vault.')
      setStatus('idle')
      setSearchParams({}, { replace: true })
    } else if (oidc === 'error') {
      setPhase('credentials')
      setStatus('error')
      setMessage('Eksterna (OIDC) prijava nije uspela. Pokušajte ponovo.')
      setSearchParams({}, { replace: true })
    }
  }, [searchParams, setSearchParams])

  function startOidc() {
    // FULL-PAGE navigacija: browser mora da prati 302 ka provajderu i primi state kolačić.
    window.location.href = oidcStartUrl()
  }

  /** OIDC: postojeća sesija + master lozinka → dohvat šifrovanog materijala → unlock u memoriji. */
  async function onOidcUnlock(event: FormEvent) {
    event.preventDefault()
    setStatus('busy')
    setMessage('')
    try {
      const [user, material] = await Promise.all([fetchMe(), fetchVaultMaterial()])
      const vault = await unlockVault(password, material)
      session.setSession(user, vault)
      setPassword('')
      setPhase('done')
      setStatus('idle')
      setMessage(`Prijavljeni ste kao "${user.username}". Vault je otključan u memoriji.`)
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  async function onCredentials(event: FormEvent) {
    event.preventDefault()
    setStatus('busy')
    setMessage('')
    try {
      const params = await fetchLoginParams(username.trim())
      const authKey = await computeAuthKey(password, params)
      const step1 = await loginStep1(username.trim(), authKey)
      setMfaTicket(step1.mfaTicket)

      if (step1.totpEnabled) {
        setPhase('totp')
        setStatus('idle')
      } else {
        // Prvi put: proviziraj TOTP (prikaži QR), pa traži kod za uključivanje.
        const setup = await totpSetup(step1.mfaTicket)
        setSetupInfo(setup)
        setPhase('totp-setup')
        setStatus('idle')
      }
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  async function onTotpSetup(event: FormEvent) {
    event.preventDefault()
    setStatus('busy')
    setMessage('')
    try {
      // Uključi TOTP pa istim kodom (isti 30s prozor) dovrši login.
      await totpVerify(mfaTicket, code)
      await finishLogin(code)
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  async function onTotp(event: FormEvent) {
    event.preventDefault()
    setStatus('busy')
    setMessage('')
    try {
      await finishLogin(code)
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  /** Step2 → otključavanje iz vraćenog vault materijala → upis u memorijsku sesiju. */
  async function finishLogin(totpCode: string) {
    const result = await loginStep2(mfaTicket, totpCode)
    const vault = await unlockVault(password, result.vault)
    session.setSession(result.user, vault)
    // Lozinka više nije potrebna — očisti je iz state-a.
    setPassword('')
    setCode('')
    setPhase('done')
    setStatus('idle')
    setMessage(`Prijavljeni ste kao "${result.user.username}". Vault je otključan u memoriji.`)
  }

  function startNewLogin() {
    session.clear()
    setUsername('')
    setMfaTicket('')
    setSetupInfo(null)
    setPhase('credentials')
    setMessage('')
    setStatus('idle')
  }

  if (phase === 'done') {
    return (
      <section style={{ maxWidth: 420 }}>
        <h2>Prijava</h2>
        <p data-testid="login-message" style={{ color: '#0a7' }}>
          {message}
        </p>
        <button type="button" onClick={startNewLogin}>
          Nova prijava
        </button>
      </section>
    )
  }

  return (
    <section style={{ maxWidth: 420 }}>
      <h2>Prijava</h2>

      {phase === 'credentials' && (
        <form onSubmit={onCredentials}>
          <label style={fieldStyle}>
            Korisničko ime
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </label>
          <label style={fieldStyle}>
            Master lozinka
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <button type="submit" disabled={busy}>
            {busy ? 'Provera...' : 'Dalje'}
          </button>
          <div style={{ marginTop: 12, borderTop: '1px solid #eee', paddingTop: 12 }}>
            <button type="button" onClick={startOidc} disabled={busy}>
              Prijava preko eksternog naloga (OIDC)
            </button>
            <p style={{ fontSize: 12, color: '#666', marginTop: 6 }}>
              OIDC daje samo sesiju — master lozinku ćete i dalje uneti da otključate vault.
            </p>
          </div>
        </form>
      )}

      {phase === 'oidc-unlock' && (
        <form onSubmit={onOidcUnlock}>
          <p style={{ fontSize: 14 }}>
            Eksterna prijava je uspešna, ali vault je i dalje zaključan. Unesite master lozinku
            da otključate ključeve (oni nikad ne napuštaju čitač).
          </p>
          <label style={fieldStyle}>
            Master lozinka
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <button type="submit" disabled={busy}>
            {busy ? 'Otključavanje...' : 'Otključaj vault'}
          </button>
        </form>
      )}

      {phase === 'totp-setup' && setupInfo && (
        <form onSubmit={onTotpSetup}>
          <p style={{ fontSize: 14 }}>
            Skenirajte QR kod u authenticator aplikaciji, pa unesite generisani kod da
            uključite drugi faktor.
          </p>
          <img src={setupInfo.qrDataUri} alt="TOTP QR kod" width={180} height={180} />
          <label style={fieldStyle}>
            TOTP kod
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              required
            />
          </label>
          <button type="submit" disabled={busy}>
            {busy ? 'Potvrda...' : 'Uključi i prijavi se'}
          </button>
        </form>
      )}

      {phase === 'totp' && (
        <form onSubmit={onTotp}>
          <p style={{ fontSize: 14 }}>Unesite kod iz authenticator aplikacije.</p>
          <label style={fieldStyle}>
            TOTP kod
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              required
            />
          </label>
          <button type="submit" disabled={busy}>
            {busy ? 'Prijava...' : 'Prijavi se'}
          </button>
        </form>
      )}

      {message && status === 'error' && (
        <p data-testid="login-message" style={{ color: '#b00020' }}>
          {message}
        </p>
      )}

      <p style={{ fontSize: 12, color: '#666' }}>
        Master lozinka nikad ne napušta čitač — serveru ide samo izvedeni dokaz (authKey).
      </p>
    </section>
  )
}

const fieldStyle: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: 4,
  marginBottom: 12,
}
