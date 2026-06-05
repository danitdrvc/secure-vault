import { useEffect, useState } from 'react'
import axios from 'axios'
import { gatewayUrl } from './config'

type BackendStatus = 'checking' | 'ok' | 'unreachable'

export default function App() {
  const [status, setStatus] = useState<BackendStatus>('checking')

  useEffect(() => {
    let cancelled = false

    axios
      .get<{ status: string }>(`${gatewayUrl}/api/health`)
      .then((res) => {
        if (!cancelled) {
          setStatus(res.data?.status === 'ok' ? 'ok' : 'unreachable')
        }
      })
      .catch(() => {
        if (!cancelled) setStatus('unreachable')
      })

    return () => {
      cancelled = true
    }
  }, [])

  const label =
    status === 'checking'
      ? 'checking...'
      : status === 'ok'
        ? 'backend: ok'
        : 'backend: unreachable'

  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', padding: 32 }}>
      <h1>Secure Vault</h1>
      <p data-testid="backend-status">{label}</p>
    </main>
  )
}
