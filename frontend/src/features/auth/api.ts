/**
 * Auth API pozivi ka gateway-u. Tela su već-šifrovani artefakti kodirani u base64
 * (vidi `registration.ts`); ovaj sloj samo šalje HTTP zahtev.
 */
import { apiClient } from '../../api/client'

/** Telo registracije — svaki kripto artefakt je base64 string (server ih čuva kao bytea). */
export interface RegisterRequest {
  username: string
  email: string
  kdfSalt: string
  kdfIterations: number
  authKey: string
  encUsk: string
  publicKey: string
  encPrivateKey: string
}

export interface RegisterResponse {
  id: string
  username: string
  email: string
  role: string
  status: string
}

export async function registerUser(request: RegisterRequest): Promise<RegisterResponse> {
  const res = await apiClient.post<RegisterResponse>('/users/register', request)
  return res.data
}
