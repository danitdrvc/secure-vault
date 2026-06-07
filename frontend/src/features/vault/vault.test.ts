// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { bootstrapKeys } from '../../crypto'
import { decryptSecret, encryptNewSecret, reencryptSecret } from './vault-crypto'

const PW = 'master-lozinka-za-test-123'
const PLAINTEXT = 'super-tajna-vrednost: API_KEY=abc123!@#'

/** Otključani ključevi kao u memorijskoj sesiji (publicKey/privateKey iz bootstrap-a). */
async function vaultKeys() {
  const { vault } = await bootstrapKeys(PW)
  return vault
}

describe('vault kripto tok (Faza 6)', () => {
  it('Create→Read round-trip vraća IDENTIČAN plaintext', async () => {
    const keys = await vaultKeys()

    const { encryptedBlob, wrappedSecretKey } = await encryptNewSecret(PLAINTEXT, keys.publicKey)
    const decrypted = await decryptSecret(encryptedBlob, wrappedSecretKey, keys.privateKey)

    expect(decrypted).toBe(PLAINTEXT)
  })

  it('encryptedBlob je nečitljiv (ne sadrži plaintext)', async () => {
    const keys = await vaultKeys()

    const { encryptedBlob, wrappedSecretKey } = await encryptNewSecret(PLAINTEXT, keys.publicKey)

    // Šifrat (base64) ne sme da sadrži plaintext; wrappedSecretKey je tačno 256B (RSA-2048).
    expect(encryptedBlob).not.toContain('API_KEY')
    expect(atob(wrappedSecretKey).length).toBe(256)
  })

  it('tuđi privatni ključ NE može da dešifruje tajnu', async () => {
    const owner = await vaultKeys()
    const other = await vaultKeys()

    const { encryptedBlob, wrappedSecretKey } = await encryptNewSecret(PLAINTEXT, owner.publicKey)

    await expect(
      decryptSecret(encryptedBlob, wrappedSecretKey, other.privateKey),
    ).rejects.toThrow()
  })

  it('reencryptSecret menja sadržaj ISTIM secretKey-em (wrap ostaje važeći)', async () => {
    const keys = await vaultKeys()
    const { encryptedBlob, wrappedSecretKey } = await encryptNewSecret(PLAINTEXT, keys.publicKey)

    const updated = 'izmenjena-vrednost-456'
    const newBlob = await reencryptSecret(updated, wrappedSecretKey, keys.privateKey)

    // Novi blob se otvara ISTIM (nepromenjenim) wrappedSecretKey-em i vraća izmenjeni plaintext.
    const decrypted = await decryptSecret(newBlob, wrappedSecretKey, keys.privateKey)
    expect(decrypted).toBe(updated)
    expect(newBlob).not.toBe(encryptedBlob)
  })
})
