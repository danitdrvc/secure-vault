import { useState } from 'react'
import type { FormEvent } from 'react'
import axios from 'axios'
import { bootstrapKeys } from '../../crypto'
import { buildRegisterRequest } from './registration'
import { registerUser } from './api'

/** Minimalna preporučena dužina master lozinke (poravnato sa security_policy default-om). */
const MIN_PASSWORD_LENGTH = 12

type FormState = 'idle' | 'submitting' | 'success' | 'error'

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
  return 'Registracija nije uspela.'
}

/**
 * Forma za registraciju. Sva kripto-derivacija je na klijentu (`bootstrapKeys`):
 * server dobija samo šifrovane artefakte i `authKey` — nikad master lozinku.
 */
export default function RegisterForm() {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [state, setState] = useState<FormState>('idle')
  const [message, setMessage] = useState('')

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    setMessage('')

    if (password.length < MIN_PASSWORD_LENGTH) {
      setState('error')
      setMessage(`Master lozinka mora imati najmanje ${MIN_PASSWORD_LENGTH} karaktera.`)
      return
    }
    if (password !== confirm) {
      setState('error')
      setMessage('Lozinke se ne poklapaju.')
      return
    }

    setState('submitting')
    try {
      // Generiše USK + RSA par i šifruje ih; vraća samo artefakte za server.
      const { artifacts } = await bootstrapKeys(password)
      const body = buildRegisterRequest(username.trim(), email.trim(), artifacts)
      const created = await registerUser(body)
      setState('success')
      setMessage(`Nalog "${created.username}" je kreiran (uloga: ${created.role}).`)
    } catch (err) {
      setState('error')
      setMessage(extractError(err))
    }
  }

  const busy = state === 'submitting'

  return (
    <section style={{ maxWidth: 420 }}>
      <h2>Registracija</h2>
      <form onSubmit={onSubmit}>
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
          Email
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            required
          />
        </label>
        <label style={fieldStyle}>
          Master lozinka
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            required
          />
          <span style={counterStyle}>
            {password.length} / min {MIN_PASSWORD_LENGTH} karaktera
          </span>
        </label>
        <label style={fieldStyle}>
          Potvrda lozinke
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            required
          />
          <span style={counterStyle}>{confirm.length} karaktera</span>
        </label>
        <button type="submit" disabled={busy}>
          {busy ? 'Kreiranje...' : 'Registruj se'}
        </button>
      </form>
      {message && (
        <p data-testid="register-message" style={{ color: state === 'error' ? '#b00020' : '#0a7' }}>
          {message}
        </p>
      )}
      <p style={{ fontSize: 12, color: '#666' }}>
        Master lozinka nikad ne napušta čitač — server prima samo šifrovane artefakte.
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

const counterStyle: React.CSSProperties = {
  fontSize: 12,
  color: '#666',
  alignSelf: 'flex-end',
}
