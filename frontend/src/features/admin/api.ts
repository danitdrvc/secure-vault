/**
 * Admin API pozivi ka gateway-u (Faza 8): upravljanje statusom naloga i sigurnosnom politikom.
 * Sve rute na backendu zahtevaju ulogu ADMIN (`@PreAuthorize`); UI ih prikazuje samo adminu, a
 * server forsira pravo nezavisno od UI-ja.
 */
import { apiClient } from '../../api/client'

/** Admin može postaviti samo ova dva stanja (FROZEN je rezervisan za honeypot okidač, Faza 10). */
export type AdminUserStatus = 'ACTIVE' | 'DEACTIVATED'

export interface AdminUser {
  id: string
  username: string
  email: string
  role: string
  status: string
}

/** Pun pregled svih naloga (`GET /admin/users`) — admin vidi sve naloge i bira cilj iz liste. */
export async function listUsers(): Promise<AdminUser[]> {
  const res = await apiClient.get<AdminUser[]>('/admin/users')
  return res.data
}

/** Aktivira/deaktivira nalog (`PATCH /admin/users/{id}/status`). */
export async function updateUserStatus(
  id: string,
  status: AdminUserStatus,
): Promise<AdminUser> {
  const res = await apiClient.patch<AdminUser>(`/admin/users/${id}/status`, { status })
  return res.data
}

/** Pun pregled aktivne politike (admin). */
export interface AdminPolicy {
  id: string
  minMasterPwLength: number
  defaultRotationDays: number
  accessTokenTtlSec: number
  refreshTokenTtlSec: number
  sessionMaxTtlSec: number
  honeypotEndpoint: boolean
  updatedById: string | null
  updatedAt: string
}

/** Parcijalna izmena politike (PATCH): pošalji samo polja koja se menjaju. */
export interface UpdatePolicyRequest {
  minMasterPwLength?: number
  defaultRotationDays?: number
  accessTokenTtlSec?: number
  refreshTokenTtlSec?: number
  sessionMaxTtlSec?: number
  honeypotEndpoint?: boolean
}

export async function fetchAdminPolicy(): Promise<AdminPolicy> {
  const res = await apiClient.get<AdminPolicy>('/admin/policy')
  return res.data
}

export async function updatePolicy(request: UpdatePolicyRequest): Promise<AdminPolicy> {
  const res = await apiClient.patch<AdminPolicy>('/admin/policy', request)
  return res.data
}
