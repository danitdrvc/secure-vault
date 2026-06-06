/**
 * Kodiranje bajtova za JSON transport (standardni base64 sa paddingom).
 *
 * Ovo NIJE kripto sloj — samo serijalizacija već šifrovanih artefakata da bi mogli da
 * putuju u JSON telu. Server očekuje isti format (`java.util.Base64` strogi dekoder).
 */
import type { Bytes } from '../crypto/bytes'

/** Bajtovi → standardni base64. */
export function bytesToBase64(bytes: Bytes): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

/** Standardni base64 → bajtovi. */
export function base64ToBytes(b64: string): Bytes {
  const binary = atob(b64)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i)
  }
  return out
}
