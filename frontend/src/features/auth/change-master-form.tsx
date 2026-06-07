import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import axios from 'axios'
import { useSession } from '../../context/session-context'
import { buildRotateMasterRequest } from './master-rotation'
import { fetchClientPolicy, fetchVaultMaterial, rotateMaster } from './api'

type Status = 'idle' | 'busy' | 'error' | 'done'

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
  return 'Promena lozinke nije uspela.'
}

/**
 * Promena master lozinke (Faza 8). Pokriva i scenario „povećana minimalna dužina": klijent
 * dohvati novu min dužinu iz politike i, ako je trenutna lozinka kraća, traži novu (dovoljno dugu).
 *
 * Sva kripto-obrada je lokalna (`buildRotateMasterRequest`): stara lozinka otključa USK, nova
 * lozinka re-šifruje samo `encUsk`/`encPrivateKey`. USK ostaje isti → sve postojeće tajne i dalje
 * rade. Serveru idu samo šifrati i dokaz stare lozinke — master lozinka NIKAD ne napušta čitač.
 */
export default function ChangeMasterForm() {
  const session = useSession()
  const [minLength, setMinLength] = useState<number | null>(null)
  const [status, setStatus] = useState<Status>('idle')
  const [message, setMessage] = useState('')

  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirm, setConfirm] = useState('')

  useEffect(() => {
    if (session.user) {
      void fetchClientPolicy()
        .then((p) => setMinLength(p.minMasterPwLength))
        .catch(() => setMinLength(null))
    }
  }, [session.user])

  if (!session.user) {
    return (
      <section style={{ maxWidth: 460 }}>
        <h2>Promena master lozinke</h2>
        <p>
          <a href="/login">Prijavite se</a> da biste promenili master lozinku.
        </p>
      </section>
    )
  }

  const currentTooShort =
    minLength != null && currentPassword.length > 0 && currentPassword.length < minLength

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    setMessage('')

    if (minLength != null && newPassword.length < minLength) {
      setStatus('error')
      setMessage(`Nova master lozinka mora imati najmanje ${minLength} karaktera.`)
      return
    }
    if (newPassword !== confirm) {
      setStatus('error')
      setMessage('Nova lozinka i potvrda se ne poklapaju.')
      return
    }

    setStatus('busy')
    try {
      // Dohvati šifrovani materijal (server ga ne može dešifrovati), re-šifruj lokalno, pošalji.
      const material = await fetchVaultMaterial()
      const request = await buildRotateMasterRequest(currentPassword, newPassword, material)
      await rotateMaster(request)
      setCurrentPassword('')
      setNewPassword('')
      setConfirm('')
      setStatus('done')
      setMessage('Master lozinka je promenjena. Postojeće tajne i dalje rade (USK je nepromenjen).')
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  return (
    <section style={{ maxWidth: 460 }}>
      <h2>Promena master lozinke</h2>
      {minLength != null && (
        <p style={{ fontSize: 13, color: '#666' }}>
          Politika zahteva najmanje <strong>{minLength}</strong> karaktera za master lozinku.
        </p>
      )}

      <form onSubmit={onSubmit}>
        <label style={fieldStyle}>
          Trenutna master lozinka
          <input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>
        {currentTooShort && (
          <p data-testid="too-short" style={{ color: '#b00020', fontSize: 13 }}>
            Trenutna lozinka je kraća od nove minimalne dužine — preporučena je promena.
          </p>
        )}
        <label style={fieldStyle}>
          Nova master lozinka
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            autoComplete="new-password"
            minLength={minLength ?? undefined}
            required
          />
        </label>
        <label style={fieldStyle}>
          Potvrda nove lozinke
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            required
          />
        </label>
        <button type="submit" disabled={status === 'busy'}>
          {status === 'busy' ? 'Menjanje...' : 'Promeni lozinku'}
        </button>
      </form>

      {message && (
        <p
          data-testid="change-master-message"
          style={{ color: status === 'error' ? '#b00020' : '#0a7' }}
        >
          {message}
        </p>
      )}
    </section>
  )
}

const fieldStyle: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: 4,
  marginBottom: 12,
}
