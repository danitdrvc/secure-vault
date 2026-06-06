import { useEffect, useState } from 'react'
import { apiClient } from '../api/client'

type BackendStatus = 'checking' | 'ok' | 'unreachable'

/** Prikazuje status backenda preko gateway proxy-ja (`/api/health`). */
export default function HealthStatus() {
  const [status, setStatus] = useState<BackendStatus>('checking')

  useEffect(() => {
    let cancelled = false

    apiClient
      .get<{ status: string }>('/health')
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

  return <p data-testid="backend-status">{label}</p>
}
