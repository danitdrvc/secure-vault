/**
 * Vault API pozivi ka gateway-u (Faza 6). Tela su već-šifrovani artefakti kodirani u base64
 * (vidi `vault-crypto.ts`); ovaj sloj samo šalje HTTP zahtev. Server vidi isključivo šifrat.
 */
import { apiClient } from '../../api/client'

/** Metapodaci tajne za listu (bez šifrata). */
export interface SecretSummary {
  id: string
  name: string
  createdAt: string
  updatedAt: string
}

/** Pun (šifrovan) sadržaj jedne tajne za prijavljenog korisnika. */
export interface SecretDetail {
  id: string
  name: string
  /** AES-256-GCM(secretKey, plaintext), base64. */
  encryptedBlob: string
  /** secretKey uvijen ka mom javnom ključu (RSA-OAEP), base64 — otvara ga samo moj privatni ključ. */
  wrappedSecretKey: string
  /** Rok rotacije u danima (`null` = bez rotacije). */
  rotationDays: number | null
  /** Vreme poslednje rotacije (ISO); klijent poredi `rotatedAt + rotationDays` sa sada. */
  rotatedAt: string
  createdAt: string
  updatedAt: string
}

export interface CreateSecretRequest {
  name: string
  encryptedBlob: string
  wrappedSecretKey: string
  /** Opcioni rok rotacije u danima (`null`/izostavljeno = bez rotacije). */
  rotationDays?: number | null
}

export interface UpdateSecretRequest {
  name: string
  encryptedBlob: string
}

/** Jedan korisnik koji ima pristup tajni (vlasnik je dohvata pre rotacije). */
export interface SecretAccessEntry {
  userId: string
}

/** Telo rotacije: nov blob + nov wrappedSecretKey za SVAKOG postojećeg primaoca. */
export interface RotateSecretRequest {
  encryptedBlob: string
  wrappedKeys: { userId: string; wrappedSecretKey: string }[]
}

export async function createSecret(request: CreateSecretRequest): Promise<SecretSummary> {
  const res = await apiClient.post<SecretSummary>('/vault/secrets', request)
  return res.data
}

export async function listSecrets(): Promise<SecretSummary[]> {
  const res = await apiClient.get<SecretSummary[]>('/vault/secrets')
  return res.data
}

export async function getSecret(id: string): Promise<SecretDetail> {
  const res = await apiClient.get<SecretDetail>(`/vault/secrets/${id}`)
  return res.data
}

export async function updateSecret(
  id: string,
  request: UpdateSecretRequest,
): Promise<SecretSummary> {
  const res = await apiClient.put<SecretSummary>(`/vault/secrets/${id}`, request)
  return res.data
}

export async function deleteSecret(id: string): Promise<void> {
  await apiClient.delete(`/vault/secrets/${id}`)
}

// ----- Faza 8: rotacija tajne (nov secretKey + re-wrap ka svim primaocima) -----

/** Lista primaoca tajne (vlasnik-only) — da bismo pri rotaciji uvili nov ključ ka svakome. */
export async function getSecretAccess(id: string): Promise<SecretAccessEntry[]> {
  const res = await apiClient.get<SecretAccessEntry[]>(`/vault/secrets/${id}/access`)
  return res.data
}

/** Rotira secretKey tajne (samo vlasnik; mora re-wrap-ovati tačno sve primaoce). */
export async function rotateSecretApi(
  id: string,
  request: RotateSecretRequest,
): Promise<SecretSummary> {
  const res = await apiClient.post<SecretSummary>(`/vault/secrets/${id}/rotate`, request)
  return res.data
}

// ----- Faza 7: sigurno deljenje (envelope) -----

/** Javni ključ korisnika (SPKI base64) — za uvijanje `secretKey` ka primaocu. */
export interface PublicKeyResponse {
  userId: string
  publicKey: string
}

export interface ShareSecretRequest {
  recipientId: string
  /** secretKey uvijen ka javnom ključu PRIMAOCA (RSA-OAEP), base64. */
  wrappedSecretKey: string
}

export interface ShareResponse {
  secretId: string
  recipientId: string
  grantedById: string
  createdAt: string
}

/** Dohvata javni ključ primaoca (`/users/{id}/public-key`). */
export async function getUserPublicKey(userId: string): Promise<PublicKeyResponse> {
  const res = await apiClient.get<PublicKeyResponse>(`/users/${userId}/public-key`)
  return res.data
}

/** Deli tajnu sa primaocem (samo TEAM_LEAD; server vraća 403 inače). */
export async function shareSecret(
  id: string,
  request: ShareSecretRequest,
): Promise<ShareResponse> {
  const res = await apiClient.post<ShareResponse>(`/vault/secrets/${id}/share`, request)
  return res.data
}
