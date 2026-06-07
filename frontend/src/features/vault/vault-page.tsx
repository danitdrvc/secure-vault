import { useCallback, useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import axios from 'axios'
import { useSession } from '../../context/session-context'
import { importPublicKey } from '../../crypto'
import { base64ToBytes } from '../../api/codec'
import {
  createSecret,
  deleteSecret,
  getSecret,
  getSecretAccess,
  getUserPublicKey,
  listSecrets,
  listUsers,
  rotateSecretApi,
  shareSecret,
  updateSecret,
} from './api'
import type { SecretSummary, UserDirectoryEntry } from './api'
import {
  decryptSecret,
  encryptNewSecret,
  reencryptSecret,
  rewrapSecretForRecipient,
  rotateSecret,
} from './vault-crypto'
import type { RotationRecipient } from './vault-crypto'
import { isRotationDue } from './rotation'

type Status = 'idle' | 'busy' | 'error'

/** Otključana tajna u memoriji (plaintext + njen wrappedSecretKey radi re-šifrovanja pri izmeni). */
interface OpenSecret {
  id: string
  plaintext: string
  wrappedSecretKey: string
  /** Da li je rok rotacije istekao (rotated_at + rotation_days u prošlosti) — prikaži upozorenje. */
  rotationDue: boolean
}

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
 * Vault stranica (Faza 6): kreiranje, listanje, čitanje (dekripcija), izmena i brisanje tajni.
 * Sva kripto-obrada je na klijentu (`vault-crypto.ts`) ključevima iz memorijske sesije —
 * server vidi samo šifrat. Bez otključanog vault-a (master lozinka) stranica ne radi.
 */
export default function VaultPage() {
  const session = useSession()
  const [secrets, setSecrets] = useState<SecretSummary[]>([])
  const [status, setStatus] = useState<Status>('idle')
  const [message, setMessage] = useState('')

  const [newName, setNewName] = useState('')
  const [newValue, setNewValue] = useState('')
  const [newRotationDays, setNewRotationDays] = useState('')

  const [open, setOpen] = useState<OpenSecret | null>(null)
  const [editName, setEditName] = useState('')

  const [shareId, setShareId] = useState<string | null>(null)
  const [recipientId, setRecipientId] = useState('')
  const [users, setUsers] = useState<UserDirectoryEntry[]>([])

  const vault = session.vault
  // Deljenje sme samo TEAM_LEAD (server to forsira @PreAuthorize-om; UI sakriva akciju ostalima).
  const canShare = session.user?.role === 'TEAM_LEAD'

  const refresh = useCallback(async () => {
    setStatus('busy')
    try {
      setSecrets(await listSecrets())
      setStatus('idle')
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }, [])

  useEffect(() => {
    if (vault) {
      void refresh()
    }
  }, [vault, refresh])

  // Imenik korisnika za padajuću listu primaoca (samo za TEAM_LEAD-a koji deli tajne).
  useEffect(() => {
    if (vault && canShare) {
      listUsers()
        .then(setUsers)
        .catch(() => setUsers([]))
    }
  }, [vault, canShare])

  if (!vault || !session.user) {
    return (
      <section style={{ maxWidth: 560 }}>
        <h2>Vault</h2>
        <p>
          Vault je zaključan. <a href="/login">Prijavite se</a> i unesite master lozinku da
          otključate ključeve (oni nikad ne napuštaju čitač).
        </p>
      </section>
    )
  }

  async function onCreate(event: FormEvent) {
    event.preventDefault()
    setStatus('busy')
    setMessage('')
    try {
      const { encryptedBlob, wrappedSecretKey } = await encryptNewSecret(newValue, vault!.publicKey)
      const rotationDays = newRotationDays.trim() === '' ? null : Number(newRotationDays)
      await createSecret({ name: newName.trim(), encryptedBlob, wrappedSecretKey, rotationDays })
      setNewName('')
      setNewValue('')
      setNewRotationDays('')
      setMessage('Tajna je sačuvana (šifrovana na klijentu).')
      await refresh()
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  async function onReveal(id: string) {
    setStatus('busy')
    setMessage('')
    try {
      const detail = await getSecret(id)
      const plaintext = await decryptSecret(detail.encryptedBlob, detail.wrappedSecretKey, vault!.privateKey)
      // Server ne okida rotaciju automatski (zero-knowledge) — klijent pri otvaranju proveri rok.
      const rotationDue = isRotationDue(detail.rotatedAt, detail.rotationDays)
      setOpen({ id, plaintext, wrappedSecretKey: detail.wrappedSecretKey, rotationDue })
      setEditName(detail.name)
      setStatus('idle')
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  /**
   * Rotacija tajne (Faza 8): nov secretKey, re-šifrovan blob i re-wrap ka SVIM primaocima.
   * Vlasnik dohvati listu primaoca i njihove javne ključeve, pa uvije nov ključ ka svakome.
   */
  async function onRotate() {
    if (!open) {
      return
    }
    setStatus('busy')
    setMessage('')
    try {
      const accessList = await getSecretAccess(open.id)
      const recipients: RotationRecipient[] = await Promise.all(
        accessList.map(async (entry) => {
          const pk = await getUserPublicKey(entry.userId)
          return { userId: entry.userId, publicKey: await importPublicKey(base64ToBytes(pk.publicKey)) }
        }),
      )
      const { encryptedBlob, wrappedKeys } = await rotateSecret(open.plaintext, recipients)
      await rotateSecretApi(open.id, { encryptedBlob, wrappedKeys })
      setOpen({ ...open, rotationDue: false })
      setMessage('Tajna je rotirana (nov ključ; stari više ne otvara novi sadržaj).')
      setStatus('idle')
      await refresh()
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  async function onSaveEdit(event: FormEvent) {
    event.preventDefault()
    if (!open) {
      return
    }
    setStatus('busy')
    setMessage('')
    try {
      // Re-šifruj istim secretKey-em (iz postojećeg wrappedSecretKey) → wrap ostaje važeći.
      const encryptedBlob = await reencryptSecret(open.plaintext, open.wrappedSecretKey, vault!.privateKey)
      await updateSecret(open.id, { name: editName.trim(), encryptedBlob })
      setOpen(null)
      setMessage('Izmene su sačuvane.')
      await refresh()
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  async function onDelete(id: string) {
    setStatus('busy')
    setMessage('')
    try {
      await deleteSecret(id)
      if (open?.id === id) {
        setOpen(null)
      }
      setMessage('Tajna je obrisana.')
      await refresh()
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  async function onShare(event: FormEvent, id: string) {
    event.preventDefault()
    setStatus('busy')
    setMessage('')
    try {
      // 1) Dohvati MOJ uvijeni secretKey za ovu tajnu. 2) Dohvati javni ključ primaoca.
      // 3) Otvori secretKey svojim privatnim ključem i ponovo ga uvij ka primaocu (envelope).
      const detail = await getSecret(id)
      const recipient = await getUserPublicKey(recipientId.trim())
      const recipientPublicKey = await importPublicKey(base64ToBytes(recipient.publicKey))
      const wrappedSecretKey = await rewrapSecretForRecipient(
        detail.wrappedSecretKey,
        vault!.privateKey,
        recipientPublicKey,
      )
      await shareSecret(id, { recipientId: recipient.userId, wrappedSecretKey })
      setShareId(null)
      setRecipientId('')
      setMessage('Tajna je podeljena (secretKey uvijen ka primaocu; blob netaknut).')
      setStatus('idle')
    } catch (err) {
      setStatus('error')
      setMessage(extractError(err))
    }
  }

  const busy = status === 'busy'

  return (
    <section style={{ maxWidth: 640 }}>
      <h2>Vault</h2>
      <p style={{ fontSize: 13, color: '#666' }}>
        Prijavljeni: <strong>{session.user.username}</strong>. Tajne se šifruju i dešifruju
        isključivo u čitaču — server čuva samo neprozirni šifrat.
      </p>

      <form onSubmit={onCreate} style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Nova tajna</h3>
        <label style={fieldStyle}>
          Naziv
          <input value={newName} onChange={(e) => setNewName(e.target.value)} required />
        </label>
        <label style={fieldStyle}>
          Sadržaj (tajna)
          <textarea
            value={newValue}
            onChange={(e) => setNewValue(e.target.value)}
            rows={3}
            required
          />
        </label>
        <label style={fieldStyle}>
          Rok rotacije u danima (opciono)
          <input
            type="number"
            min={1}
            value={newRotationDays}
            onChange={(e) => setNewRotationDays(e.target.value)}
            placeholder="npr. 90 — prazno = bez rotacije"
          />
        </label>
        <button type="submit" disabled={busy}>
          {busy ? 'Šifrovanje...' : 'Sačuvaj tajnu'}
        </button>
      </form>

      <h3>Moje tajne</h3>
      {secrets.length === 0 ? (
        <p style={{ color: '#666' }}>Još nema tajni.</p>
      ) : (
        <ul style={{ listStyle: 'none', padding: 0 }}>
          {secrets.map((secret) => (
            <li key={secret.id} style={cardStyle}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                <strong>{secret.name}</strong>
                <span style={{ display: 'flex', gap: 8 }}>
                  <button type="button" onClick={() => onReveal(secret.id)} disabled={busy}>
                    Prikaži
                  </button>
                  {canShare && (
                    <button
                      type="button"
                      onClick={() => {
                        setShareId(shareId === secret.id ? null : secret.id)
                        setRecipientId('')
                      }}
                      disabled={busy}
                    >
                      Podeli
                    </button>
                  )}
                  <button type="button" onClick={() => onDelete(secret.id)} disabled={busy}>
                    Obriši
                  </button>
                </span>
              </div>

              {canShare && shareId === secret.id && (
                <form onSubmit={(e) => onShare(e, secret.id)} style={{ marginTop: 12 }}>
                  <label style={fieldStyle}>
                    Primalac (korisnik)
                    <select
                      value={recipientId}
                      onChange={(e) => setRecipientId(e.target.value)}
                      required
                    >
                      <option value="" disabled>
                        — izaberite korisnika —
                      </option>
                      {users
                        .filter((u) => u.id !== session.user?.id)
                        .map((u) => (
                          <option key={u.id} value={u.id}>
                            {u.username} ({u.role})
                          </option>
                        ))}
                    </select>
                  </label>
                  <span style={{ display: 'flex', gap: 8 }}>
                    <button type="submit" disabled={busy}>
                      Podeli tajnu
                    </button>
                    <button type="button" onClick={() => setShareId(null)} disabled={busy}>
                      Otkaži
                    </button>
                  </span>
                </form>
              )}

              {open?.id === secret.id && (
                <form onSubmit={onSaveEdit} style={{ marginTop: 12 }}>
                  {open.rotationDue && (
                    <div
                      data-testid={`rotation-warning-${secret.id}`}
                      style={{
                        border: '1px solid #f0c000',
                        background: '#fff8e1',
                        borderRadius: 6,
                        padding: 10,
                        marginBottom: 12,
                      }}
                    >
                      <span style={{ color: '#8a6d00' }}>
                        ⚠️ Tajna je istekla — preporučena rotacija.
                      </span>
                      <div style={{ marginTop: 8 }}>
                        <button type="button" onClick={onRotate} disabled={busy}>
                          Rotiraj sada
                        </button>
                      </div>
                    </div>
                  )}
                  <label style={fieldStyle}>
                    Naziv
                    <input value={editName} onChange={(e) => setEditName(e.target.value)} required />
                  </label>
                  <label style={fieldStyle}>
                    Sadržaj (dešifrovan u memoriji)
                    <textarea
                      data-testid={`secret-plaintext-${secret.id}`}
                      value={open.plaintext}
                      onChange={(e) => setOpen({ ...open, plaintext: e.target.value })}
                      rows={3}
                    />
                  </label>
                  <span style={{ display: 'flex', gap: 8 }}>
                    <button type="submit" disabled={busy}>
                      Sačuvaj izmene
                    </button>
                    <button type="button" onClick={() => setOpen(null)} disabled={busy}>
                      Zatvori
                    </button>
                  </span>
                </form>
              )}
            </li>
          ))}
        </ul>
      )}

      {message && (
        <p data-testid="vault-message" style={{ color: status === 'error' ? '#b00020' : '#0a7' }}>
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
