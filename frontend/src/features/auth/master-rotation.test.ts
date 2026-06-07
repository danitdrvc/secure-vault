// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { bootstrapKeys, rotateMasterKey, unlock } from '../../crypto'
import { decryptSecret, encryptNewSecret } from '../vault/vault-crypto'

const OLD_PW = 'stara-master-lozinka-123'
const NEW_PW = 'nova-duza-master-lozinka-456789'

// Rotacija lanča više PBKDF2 (600k iter) derivacija + RSA keygen po testu — dignut timeout.
const CRYPTO_TIMEOUT_MS = 30_000

/** Sirovi USK bajtovi (radi poređenja da rotacija ne menja radni ključ). */
async function uskRaw(usk: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', usk))
}

describe('promena master lozinke (Faza 8) — rotateMasterKey', () => {
  it('NOVA lozinka otključava ISTI USK; STARA lozinka više ne otključava', async () => {
    const { artifacts, vault } = await bootstrapKeys(OLD_PW)
    const originalUsk = await uskRaw(vault.usk)

    const rotated = await rotateMasterKey(
      OLD_PW,
      NEW_PW,
      artifacts.kdfSalt,
      artifacts.kdfIterations,
      artifacts.encUsk,
      artifacts.encPrivateKey,
    )

    // Nova lozinka + novi (re-šifrovani) artefakti → IDENTIČAN USK.
    const unlocked = await unlock(
      NEW_PW,
      rotated.kdfSalt,
      rotated.kdfIterations,
      rotated.encUsk,
      rotated.encPrivateKey,
    )
    expect(await uskRaw(unlocked.usk)).toEqual(originalUsk)

    // Stara lozinka ne otključava nove artefakte (KEK je drugačiji → AES-GCM auth pada).
    await expect(
      unlock(OLD_PW, rotated.kdfSalt, rotated.kdfIterations, rotated.encUsk, rotated.encPrivateKey),
    ).rejects.toThrow()
  }, CRYPTO_TIMEOUT_MS)

  it('postojeća tajna se otvara i posle promene lozinke (blob/USK netaknuti)', async () => {
    const { artifacts, vault } = await bootstrapKeys(OLD_PW)
    const enc = await encryptNewSecret('API_KEY=pre-promene-123', vault.publicKey)

    const rotated = await rotateMasterKey(
      OLD_PW,
      NEW_PW,
      artifacts.kdfSalt,
      artifacts.kdfIterations,
      artifacts.encUsk,
      artifacts.encPrivateKey,
    )

    // Posle promene lozinke unlock NOVOM lozinkom rekonstruiše privatni ključ koji otvara
    // tajnu šifrovanu PRE promene — envelope (secretKey/blob) je netaknut.
    const unlocked = await unlock(
      NEW_PW,
      rotated.kdfSalt,
      rotated.kdfIterations,
      rotated.encUsk,
      rotated.encPrivateKey,
    )
    const plaintext = await decryptSecret(enc.encryptedBlob, enc.wrappedSecretKey, unlocked.privateKey)
    expect(plaintext).toBe('API_KEY=pre-promene-123')
  }, CRYPTO_TIMEOUT_MS)

  it('pogrešna stara lozinka pri rotaciji baca grešku (ne curi materijal)', async () => {
    const { artifacts } = await bootstrapKeys(OLD_PW)
    await expect(
      rotateMasterKey(
        'pogresna-lozinka',
        NEW_PW,
        artifacts.kdfSalt,
        artifacts.kdfIterations,
        artifacts.encUsk,
        artifacts.encPrivateKey,
      ),
    ).rejects.toThrow()
  }, CRYPTO_TIMEOUT_MS)

  it('currentAuthKey iz rotacije = authKey koji bi server čuvao za STARU lozinku', async () => {
    // bootstrap proizvodi authKey za staru lozinku; rotacija mora vratiti ISTI currentAuthKey
    // (dokaz stare lozinke koji server poredi sa auth_hash pre primene).
    const { artifacts } = await bootstrapKeys(OLD_PW)
    const rotated = await rotateMasterKey(
      OLD_PW,
      NEW_PW,
      artifacts.kdfSalt,
      artifacts.kdfIterations,
      artifacts.encUsk,
      artifacts.encPrivateKey,
    )
    expect(rotated.currentAuthKey).toEqual(artifacts.authKey)
    // Novi authKey se razlikuje (izveden iz nove lozinke + svežeg salta).
    expect(rotated.authKey).not.toEqual(artifacts.authKey)
  }, CRYPTO_TIMEOUT_MS)
})
