import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import axios from 'axios'
import { useSession } from '../../context/session-context'
import {
  fetchAdminPolicy,
  updatePolicy,
  updateUserStatus,
} from './api'
import type { AdminPolicy, AdminUserStatus, UpdatePolicyRequest } from './api'

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
  return 'Operacija nije uspela.'
}

/**
 * Admin stranica (Faza 8). Admin SAMO aktivira/deaktivira naloge i menja sigurnosnu politiku —
 * NIKAD ne upravlja tajnama (vault ostaje zero-knowledge i za admina). Stranica je vidljiva samo
 * ulozi ADMIN; server forsira pravo nezavisno od UI-ja (`@PreAuthorize`).
 */
export default function AdminPage() {
  const session = useSession()
  const isAdmin = session.user?.role === 'ADMIN'

  const [status, setStatus] = useState<Status>('idle')
  const [message, setMessage] = useState('')

  const [targetUserId, setTargetUserId] = useState('')

  const [policy, setPolicy] = useState<AdminPolicy | null>(null)
  const [form, setForm] = useState<UpdatePolicyRequest>({})

  const loadPolicy = useCallback(async () => {
    setStatus('busy')
    try {
      const p = await fetchAdminPolicy()
      setPolicy(p)
      setForm({
        minMasterPwLength: p.minMasterPwLength,
        defaultRotationDays: p.defaultRotationDays,
        accessTokenTtlSec: p.accessTokenTtlSec,
        refreshTokenTtlSec: p.refreshTokenTtlSec,
        sessionMaxTtlSec: p.sessionMaxTtlSec,
        honeypotEndpoint: p.honeypotEndpoint,
      })
      setStatus('idle')
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }, [])

  useEffect(() => {
    if (isAdmin) {
      void loadPolicy()
    }
  }, [isAdmin, loadPolicy])

  if (!session.user || !isAdmin) {
    return (
      <section style={{ maxWidth: 560 }}>
        <h2>Admin</h2>
        <p>Ova stranica je dostupna samo administratorima.</p>
      </section>
    )
  }

  async function onStatus(nextStatus: AdminUserStatus) {
    setStatus('busy')
    setMessage('')
    try {
      const updated = await updateUserStatus(targetUserId.trim(), nextStatus)
      setMessage(`Nalog "${updated.username}" je sada ${updated.status}.`)
      setStatus('idle')
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  async function onSavePolicy(event: FormEvent) {
    event.preventDefault()
    setStatus('busy')
    setMessage('')
    try {
      const saved = await updatePolicy(form)
      setPolicy(saved)
      setMessage('Sigurnosna politika je sačuvana.')
      setStatus('idle')
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  const busy = status === 'busy'

  /** Helper za numerička polja politike. */
  function numberField(label: string, key: keyof UpdatePolicyRequest, hint?: string) {
    return (
      <label style={fieldStyle}>
        {label}
        <input
          type="number"
          value={form[key] === undefined ? '' : String(form[key])}
          onChange={(e) =>
            setForm({ ...form, [key]: e.target.value === '' ? undefined : Number(e.target.value) })
          }
        />
        {hint && <span style={{ fontSize: 12, color: '#666' }}>{hint}</span>}
      </label>
    )
  }

  return (
    <section style={{ maxWidth: 640 }}>
      <h2>Admin</h2>
      <p style={{ fontSize: 13, color: '#666' }}>
        Admin upravlja samo statusom naloga i sigurnosnom politikom — nikad tajnama.
      </p>

      <div style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Status naloga</h3>
        <label style={fieldStyle}>
          ID korisnika (UUID)
          <input
            value={targetUserId}
            onChange={(e) => setTargetUserId(e.target.value)}
            placeholder="UUID korisnika"
          />
        </label>
        <span style={{ display: 'flex', gap: 8 }}>
          <button type="button" onClick={() => onStatus('ACTIVE')} disabled={busy || !targetUserId.trim()}>
            Aktiviraj
          </button>
          <button
            type="button"
            onClick={() => onStatus('DEACTIVATED')}
            disabled={busy || !targetUserId.trim()}
          >
            Deaktiviraj
          </button>
        </span>
        <p style={{ fontSize: 12, color: '#666' }}>
          Deaktiviran nalog ne može da se uloguje (server odbija već u prvom koraku login-a).
        </p>
      </div>

      <form onSubmit={onSavePolicy} style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Sigurnosna politika</h3>
        {numberField('Min. dužina master lozinke', 'minMasterPwLength')}
        {numberField('Podrazumevani rok rotacije (dani)', 'defaultRotationDays')}
        {numberField('Access token TTL (s)', 'accessTokenTtlSec', 'Tehnički prozor rotacije.')}
        {numberField('Refresh token TTL (s)', 'refreshTokenTtlSec', 'Trajanje pojedinačnog refresh tokena.')}
        {numberField(
          'Trajanje sesije / apsolutni cap (s)',
          'sessionMaxTtlSec',
          'Posle ovog vremena od logina sledi obavezan ponovni login.',
        )}
        <label style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 }}>
          <input
            type="checkbox"
            checked={form.honeypotEndpoint ?? false}
            onChange={(e) => setForm({ ...form, honeypotEndpoint: e.target.checked })}
          />
          Honeypot test-endpoint uključen (demonstracija SQLi — Faza 10)
        </label>
        <button type="submit" disabled={busy}>
          {busy ? 'Čuvanje...' : 'Sačuvaj politiku'}
        </button>
        {policy && (
          <p style={{ fontSize: 12, color: '#666', marginTop: 8 }}>
            Poslednja izmena: {new Date(policy.updatedAt).toLocaleString()}
          </p>
        )}
      </form>

      {message && (
        <p data-testid="admin-message" style={{ color: status === 'error' ? '#b00020' : '#0a7' }}>
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

const cardStyle: React.CSSProperties = {
  border: '1px solid #e2e2e2',
  borderRadius: 8,
  padding: 16,
  marginBottom: 16,
}
