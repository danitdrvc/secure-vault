/**
 * Auth API pozivi ka gateway-u. Tela su već-šifrovani artefakti kodirani u base64
 * (vidi `registration.ts`); ovaj sloj samo šalje HTTP zahtev.
 */
import { apiClient } from '../../api/client'
import { gatewayUrl } from '../../config'

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

// ----- Faza 4: login (lozinka + TOTP + sesija) -----

/** KDF parametri da klijent izvede `authKey` pre dokaza identiteta. */
export interface LoginParamsResponse {
  kdfSalt: string
  kdfIterations: number
}

export interface LoginStep1Response {
  mfaTicket: string
  mfaRequired: boolean
  totpEnabled: boolean
}

export interface TotpSetupResponse {
  otpauthUri: string
  qrDataUri: string
}

export interface AuthUser {
  id: string
  username: string
  email: string
  role: string
  status: string
}

/** Šifrovani vault materijal za klijentsko `unlock` (sve base64, server ga ne dešifruje). */
export interface VaultMaterial {
  kdfSalt: string
  kdfIterations: number
  encUsk: string
  publicKey: string
  encPrivateKey: string
}

export interface LoginStep2Response {
  user: AuthUser
  vault: VaultMaterial
}

export async function fetchLoginParams(username: string): Promise<LoginParamsResponse> {
  const res = await apiClient.post<LoginParamsResponse>('/auth/login/params', { username })
  return res.data
}

export async function loginStep1(username: string, authKey: string): Promise<LoginStep1Response> {
  const res = await apiClient.post<LoginStep1Response>('/auth/login/step1', { username, authKey })
  return res.data
}

export async function totpSetup(mfaTicket: string): Promise<TotpSetupResponse> {
  const res = await apiClient.post<TotpSetupResponse>('/auth/totp/setup', { mfaTicket })
  return res.data
}

export async function totpVerify(mfaTicket: string, totpCode: string): Promise<void> {
  await apiClient.post('/auth/totp/verify', { mfaTicket, totpCode })
}

export async function loginStep2(mfaTicket: string, totpCode: string): Promise<LoginStep2Response> {
  const res = await apiClient.post<LoginStep2Response>('/auth/login/step2', { mfaTicket, totpCode })
  return res.data
}

/** Rotira sesiju (čita/postavlja HttpOnly kolačiće); telo je prazno. */
export async function refreshSession(): Promise<void> {
  await apiClient.post('/auth/refresh')
}

export async function fetchMe(): Promise<AuthUser> {
  const res = await apiClient.get<AuthUser>('/auth/me')
  return res.data
}

// ----- Faza 5: OIDC prijava -----

/**
 * URL za pokretanje OIDC prijave. Mora biti FULL-PAGE navigacija (`window.location`), ne XHR —
 * backend odgovara 302 redirect-om na eksternog provajdera, a browser mora da ga prati i da
 * primi `SameSite=Lax` state kolačić. (`/api` prefiks: gateway mapira `/api/**` → backend.)
 */
export function oidcStartUrl(): string {
  return `${gatewayUrl}/api/auth/oidc/start`
}

/**
 * Šifrovani vault materijal za autentikovanu sesiju (posle OIDC prijave). Sam materijal je
 * beskoristan bez master lozinke — klijent ga koristi da lokalno pozove `unlock`.
 */
export async function fetchVaultMaterial(): Promise<VaultMaterial> {
  const res = await apiClient.get<VaultMaterial>('/auth/vault-material')
  return res.data
}

// ----- Faza 8: politika (klijentski podskup) + promena master lozinke -----

/** Klijentski podskup sigurnosne politike (`GET /policy`). */
export interface ClientPolicy {
  minMasterPwLength: number
  defaultRotationDays: number
}

export async function fetchClientPolicy(): Promise<ClientPolicy> {
  const res = await apiClient.get<ClientPolicy>('/policy')
  return res.data
}

/** Telo za promenu master lozinke — svi kripto artefakti su base64 (server ih čuva kao bytea). */
export interface RotateMasterRequest {
  /** Dokaz STARE lozinke (step-up re-auth). */
  currentAuthKey: string
  authKey: string
  kdfSalt: string
  kdfIterations: number
  encUsk: string
  encPrivateKey: string
}

/** Promena master lozinke (`POST /auth/rotate-master`); telo je prazno na uspeh (204). */
export async function rotateMaster(request: RotateMasterRequest): Promise<void> {
  await apiClient.post('/auth/rotate-master', request)
}
