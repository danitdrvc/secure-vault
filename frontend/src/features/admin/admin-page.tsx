import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import axios from 'axios'
import { useSession } from '../../context/session-context'
import {
  anchorAudit,
  fetchAdminPolicy,
  fetchAuditAnchors,
  fetchAuditEntries,
  listUsers,
  updatePolicy,
  updateUserStatus,
  verifyAudit,
} from './api'
import type {
  AdminPolicy,
  AdminUser,
  AdminUserStatus,
  AuditAnchor,
  AuditEntry,
  AuditVerification,
  UpdatePolicyRequest,
} from './api'

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
  const [users, setUsers] = useState<AdminUser[]>([])

  const [policy, setPolicy] = useState<AdminPolicy | null>(null)
  const [form, setForm] = useState<UpdatePolicyRequest>({})

  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [verification, setVerification] = useState<AuditVerification | null>(null)
  const [anchors, setAnchors] = useState<AuditAnchor[]>([])

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

  const loadUsers = useCallback(async () => {
    try {
      setUsers(await listUsers())
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }, [])

  const loadAudit = useCallback(async () => {
    try {
      const [entries, check, anchorList] = await Promise.all([
        fetchAuditEntries(),
        verifyAudit(),
        fetchAuditAnchors(),
      ])
      setAudit(entries)
      setVerification(check)
      setAnchors(anchorList)
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }, [])

  useEffect(() => {
    if (isAdmin) {
      void loadPolicy()
      void loadUsers()
      void loadAudit()
    }
  }, [isAdmin, loadPolicy, loadUsers, loadAudit])

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
      await loadUsers()
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  async function onAnchor() {
    setStatus('busy')
    setMessage('')
    try {
      const anchor = await anchorAudit()
      setMessage(`Lanac je sidren: seq ${anchor.fromSeq}..${anchor.toSeq} (kanal: ${anchor.channel}).`)
      setStatus('idle')
      await loadAudit()
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
    <section style={{ maxWidth: 820 }}>
      <h2>Admin</h2>
      <p style={{ fontSize: 13, color: '#666' }}>
        Admin upravlja samo statusom naloga i sigurnosnom politikom — nikad tajnama.
      </p>

      <div style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Status naloga</h3>
        <label style={fieldStyle}>
          Nalog
          <select value={targetUserId} onChange={(e) => setTargetUserId(e.target.value)}>
            <option value="" disabled>
              — izaberite nalog —
            </option>
            {users.map((u) => (
              <option key={u.id} value={u.id}>
                {u.username} — {u.role} — {u.status}
              </option>
            ))}
          </select>
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
          Honeypot test-endpoint uključen
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

      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
          <h3 style={{ margin: 0 }}>Audit log (imutabilni hash-lanac)</h3>
          <span style={{ display: 'flex', gap: 8 }}>
            <button type="button" onClick={onAnchor} disabled={busy}>
              Sidri lanac
            </button>
            <button type="button" onClick={() => void loadAudit()} disabled={busy}>
              Osveži
            </button>
          </span>
        </div>

        {verification && (
          <p
            data-testid="audit-verify"
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: verification.valid ? '#0a7' : '#b00020',
            }}
          >
            {verification.valid
              ? `✓ Lanac je netaknut — provereno ${verification.verifiedCount} zapisa.`
              : `✗ Lanac je narušen na seq ${verification.brokenAtSeq} (provereno ${verification.verifiedCount}).`}
          </p>
        )}

        {audit.length === 0 ? (
          <p style={{ color: '#666' }}>Još nema audit zapisa.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ borderCollapse: 'collapse', width: '100%', fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={thStyle}>seq</th>
                  <th style={thStyle}>Vreme (UTC)</th>
                  <th style={thStyle}>Akcija</th>
                  <th style={thStyle}>Resurs</th>
                  <th style={thStyle}>Actor</th>
                  <th style={thStyle}>Hash</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((e) => (
                  <tr key={e.seq}>
                    <td style={tdStyle}>{e.seq}</td>
                    <td style={tdStyle}>{new Date(e.createdAt).toLocaleString()}</td>
                    <td style={tdStyle}>{e.action}</td>
                    <td style={tdStyle}>{e.resource ?? '—'}</td>
                    <td style={tdStyle} title={e.actorId ?? ''}>
                      {e.actorId ? e.actorId.slice(0, 8) : '—'}
                    </td>
                    <td style={{ ...tdStyle, fontFamily: 'monospace' }} title={e.hash}>
                      {e.hash.slice(0, 12)}…
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p style={{ fontSize: 12, color: '#666', marginTop: 8 }}>
          Prikazano poslednjih {audit.length} zapisa (najnoviji prvi). Zapisi su append-only — ne
          mogu se izmeniti ni obrisati; svaka tiha izmena prekida hash-lanac i obara proveru.
        </p>

        <h4 style={{ marginBottom: 4 }}>Sidra lanca (anchoring)</h4>
        <p style={{ fontSize: 12, color: '#666', marginTop: 0 }}>
          „Sidri lanac" šalje vrh lanca (head hash) na nezavisan kanal (email/log) i upisuje trag
          ovde. Sačuvani head hash van baze otkriva i potpuno prepisivanje loga — ne samo tihu izmenu.
        </p>
        {anchors.length === 0 ? (
          <p style={{ color: '#666', fontSize: 13 }}>Lanac još nije sidren.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ borderCollapse: 'collapse', width: '100%', fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={thStyle}>Vreme</th>
                  <th style={thStyle}>Opseg (seq)</th>
                  <th style={thStyle}>Kanal</th>
                  <th style={thStyle}>Head hash</th>
                </tr>
              </thead>
              <tbody>
                {anchors.map((a) => (
                  <tr key={a.id}>
                    <td style={tdStyle}>{new Date(a.createdAt).toLocaleString()}</td>
                    <td style={tdStyle}>
                      {a.fromSeq}..{a.toSeq}
                    </td>
                    <td style={tdStyle}>{a.channel}</td>
                    <td style={{ ...tdStyle, fontFamily: 'monospace' }} title={a.headHash}>
                      {a.headHash.slice(0, 12)}…
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {message && (
        <p data-testid="admin-message" style={{ color: status === 'error' ? '#b00020' : '#0a7' }}>
          {message}
        </p>
      )}
    </section>
  )
}

const thStyle: React.CSSProperties = {
  textAlign: 'left',
  borderBottom: '2px solid #ddd',
  padding: '6px 8px',
  whiteSpace: 'nowrap',
}

const tdStyle: React.CSSProperties = {
  borderBottom: '1px solid #eee',
  padding: '6px 8px',
  whiteSpace: 'nowrap',
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
