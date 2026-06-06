# PROGRESS — Secure Vault

Status implementacije po fazama (vidi `DEVELOPMENT_PLAN.md`).

- [x] Faza 0  — Setup i Konfiguracija
- [x] Faza 1  — Data Layer i Migracije
- [x] Faza 2  — Klijentski Kripto Sloj
- [x] Faza 3  — Registracija i Skladištenje Ključeva
- [x] Faza 4  — Autentikacija (lozinka + MFA + sesije)
- [ ] Faza 5  — OIDC Prijava
- [ ] Faza 6  — Vault CRUD
- [ ] Faza 7  — Sigurno Deljenje
- [ ] Faza 8  — Admin i Sigurnosne Politike
- [ ] Faza 9  — API Gateway i Rate Limiting
- [ ] Faza 10 — Honeypot i Honeytokens
- [ ] Faza 11 — Imutable Audit Log
- [ ] Faza 12 — Integracija i Dockerizacija

---

## Faza 0 — Setup i Konfiguracija

**Šta je urađeno:**
- Monorepo struktura: `backend/` (Spring Boot), `gateway/` (Spring Cloud Gateway), `frontend/` (React + Vite).
- `docker-compose.yml` sa 5 servisa: `postgres`, `redis`, `backend`, `gateway`, `frontend`.
- `.env.example` (DB/Redis URL, JWT_SECRET, SERVER_KMS_KEY, OIDC_*, ACCESS_TTL, routing).
- Backend: `GET /health` -> `200 {"status":"ok"}` (port 8081).
- Gateway: sopstveni `/health` + ruta `/api/**` -> backend (StripPrefix), CORS na frontend origin (port 8080).
- Frontend: Vite + React skeleton gađa `${VITE_GATEWAY_URL}/api/health` i prikazuje "backend: ok".
- Testovi: `HealthControllerTest` (backend), `GatewayApplicationTests` (gateway), `config.test.ts` (frontend).

**Acceptance Criteria:**
- [x] `curl http://localhost:8080/health` -> `200 {"status":"ok"}`; `curl http://localhost:8080/api/health` proxy-uje backend. *(verifikovano lokalno: backend 8081, gateway 8080, proxy i CORS preflight sa :5173 svi 200)*
- [x] Frontend na `http://localhost:5173` prikazuje "backend: ok". *(dev server + build + logika verifikovani; vizuelno potvrđeno u browseru)*
- [ ] `docker compose up --build` diže svih 5 servisa bez grešaka. **ODLOŽENO:** instalacija Docker Desktop-a pala je na oštećenom Windows component store-u (DISM `0x800f0915` / `14098`). Compose fajlovi su spremni i ispravni; kriterijum se potvrđuje kad se Docker osposobi (popravka preko Win11 ISO izvora).

**Lokalni dev setup (umesto Dockera, za sada):**
- JDK 21 (Temurin) + Maven 3.9.9 (u `~/tools`), `JAVA_HOME` i PATH podešeni na korisničkom nivou.
- Pokretanje: `mvn spring-boot:run` u `backend/` i `gateway/`, `npm run dev` u `frontend/`.

---

## Faza 1 — Data Layer i Migracije

**Šta je urađeno:**
- `backend/pom.xml`: dodati `spring-boot-starter-data-jpa`, `flyway-core` + `flyway-database-postgresql`,
  `postgresql` (runtime); za test `io.zonky.test:embedded-database-spring-test` + `embedded-postgres`
  + Windows binar (PG16, preko `embedded-postgres-binaries-bom`).
- `application.yml`: `datasource` (env `DB_URL`/`POSTGRES_USER`/`POSTGRES_PASSWORD`, lokalni default
  `jdbc:postgresql://localhost:5432/securevault`, `vault/vault`), `jpa.hibernate.ddl-auto=validate`
  (Flyway je vlasnik šeme), `flyway.enabled=true` (auto-migrate na startu).
- `db/migration/V1__init.sql`: kompletan DDL iz sekcije 3.2 (9 tabela + indeksi + `pgcrypto`).
- `db/migration/V2__seed.sql`: idempotentan seed — 1 `ADMIN` (placeholder kripto polja: nasumični
  bajtovi samo da zadovolje NOT NULL; prave vrednosti nastaju na klijentu u Fazi 3/4), 1 aktivna
  `security_policy`, 3 `honeytoken` reda.
- JPA entiteti za svih 9 tabela (per-feature `domain/`): `User` (+`Role`,`UserStatus`), `Secret`,
  `SecretAccess`, `SecurityPolicy`, `AuditLog`, `AuditAnchor`, `Honeytoken`, `SecurityEvent`, `RefreshToken`.
  Mapiranja: `byte[]`↔`bytea`, `String`↔`jsonb` (`@JdbcTypeCode(JSON)`), enum↔`varchar` (STRING),
  `OffsetDateTime`↔`timestamptz`, `bigserial` (audit `seq`) read-only.
- Spring Data JPA repozitorijumi po feature-u (`repository/`): `UserRepository`, `SecretRepository`,
  `SecretAccessRepository`, `SecurityPolicyRepository`, `AuditLogRepository`, `AuditAnchorRepository`,
  `HoneytokenRepository`, `SecurityEventRepository`, `RefreshTokenRepository`.
- Testovi nad PRAVIM (embedded) Postgresom umesto H2 (meta-anotacija `@EmbeddedPostgresJpaTest`):
  `FlywayMigrationTest`, `SeedDataTest`, `UserRepositoryTest`.

**Acceptance Criteria:**
- [x] `flyway info` pokazuje sve migracije primenjene ("Success"). *(`FlywayMigrationTest`: nema
  `pending`, V1 i V2 `applied`. Implicitno: `ddl-auto=validate` prolazi → entiteti se poklapaju sa šemom.)*
- [x] Seed prolazi; `SELECT count(*) FROM security_policy WHERE is_active = true` = 1. *(`SeedDataTest`.)*
- [x] Unit test (`@DataJpaTest`): repozitorijum može da kreira i pročita `User` red. *(`UserRepositoryTest`.)*

**Verifikacija:** `mvn -f backend/pom.xml test` → BUILD SUCCESS, 7 testova, 0 grešaka
(embedded PG16 binar — bez Dockera, bez lokalnog PG servisa).

**Živi lokalni DB (verifikovano 2026-06-06):** kreirani rola `vault` + baza `securevault` +
`pgcrypto` u lokalnom Postgres 17. Na startu (`spring-boot:run`) Flyway ispisuje
`Successfully applied 2 migrations ... now at version v2`; `flyway_schema_history` V1+V2 = success;
živi `SELECT count(*) FROM security_policy WHERE is_active = true` = 1; admin + 3 honeytokena prisutni.
(Testovi su hermetični i ne zavise od ovoga.)

---

## Faza 2 — Klijentski Kripto Sloj

**Šta je urađeno:**
- Reuzabilan, testiran kripto modul na frontendu (`frontend/src/crypto/`), isključivo nad
  ugrađenim **Web Crypto API** (`crypto.subtle`) — nula eksternih kripto biblioteka, bez
  sopstvenih implementacija algoritama. Sloj NE dodiruje mrežu (čista memorija čitača).
- `kdf.ts` — `deriveMasterKey(pw, salt, iterations)`: PBKDF2-HMAC-SHA256 (default 600k iteracija)
  → non-extractable HKDF bazni ključ (IKM za razdvajanje namena).
- `derive.ts` — `deriveKek(masterKey)` (HKDF `info="vault-kek"` → AES-256-GCM KEK) i
  `deriveAuthKey(masterKey)` (HKDF `info="vault-auth"` → 32B authKey za server). Razdvajanje
  namena `info` labelama: znanje jednog materijala ne otkriva drugi.
- `sym.ts` — `aesGcmEncrypt/Decrypt` (AES-256-GCM), format `nonce(12B) || ciphertext(+tag)`;
  slučajan nonce po pozivu; neuspeh auth taga → `CryptoError` (bez tihog fallback-a).
  `importAesGcmKey` helper.
- `asym.ts` — `generateKeyPair()` (RSA-OAEP 2048, SHA-256), `wrapTo(publicKey, data)`,
  `unwrap(privateKey, box)` + SPKI/PKCS8 export/import helperi.
- `vault.ts` — visoke funkcije: `bootstrapKeys(pw)` (slučajan USK + RSA par → vraća
  `RegistrationArtifacts` za server: `kdfSalt/kdfIterations/authKey/encUsk/publicKey/encPrivateKey`,
  i `UnlockedVault` za memoriju) i `unlock(pw, salt, iterations, encUsk, encPrivateKey)` koji
  rekonstruiše USK i privatni ključ. Slojevi: `encUsk=AES-GCM(KEK,USK)`,
  `encPrivateKey=AES-GCM(USK, priv)`.
- `bytes.ts` — `Bytes = Uint8Array<ArrayBuffer>` alias (Web Crypto `BufferSource` traži
  `ArrayBuffer`-backed poglede; TS 5.9 typed-array generika). `errors.ts` — `CryptoError`.
  `index.ts` — barrel.
- Vitest testovi (env `node`, pun WebCrypto): `sym.test.ts`, `asym.test.ts`, `vault.test.ts`,
  `no-network.test.ts`.

**Acceptance Criteria:**
- [x] `unlock(bootstrap output)` rekonstruiše ISTI USK i privatni ključ (round-trip).
  *(`vault.test.ts`: identičan `exportKey('raw')` USK; privatni ključ otvara box uvijen ka
  objavljenom javnom ključu.)*
- [x] `wrapTo(pubB, x)` → `unwrap(privB)` = `x`; privatni ključ A NE otvara box za B.
  *(`asym.test.ts`; cross-ključ → `CryptoError`.)*
- [x] AES-GCM dekripcija pogrešnim ključem baca grešku (autentikacija radi).
  *(`sym.test.ts`: pogrešan ključ i izmenjen šifrat → `CryptoError`.)*
- [x] Negativan test: nijedna funkcija ne emituje ništa kroz mrežu.
  *(`no-network.test.ts`: `fetch`/`XMLHttpRequest` mock-ovani da pucaju; pun tok prolazi
  bez ijednog poziva.)*

**Verifikacija:** `npm test` (u `frontend/`) → **5 test fajlova, 13 testova, 0 grešaka**.
`npm run build` (`tsc && vite build`) → čist type-check + build.

---

## Faza 3 — Registracija i Skladištenje Ključeva

**Šta je urađeno:**
- **Backend `user` modul** — `POST /users/register` (`UserController` → `UserService` →
  `UserRepository`). Prima `{username, email, kdfSalt, kdfIterations, authKey, encUsk,
  publicKey, encPrivateKey}`; vraća `201` + `RegisterResponse` (samo `id/username/email/
  role/status` — NIKAD kripto materijal). Novi nalog: `role=DEVELOPER`, `status=ACTIVE`.
- **Zero-knowledge skladištenje** — server čuva SAMO `bcrypt(authKey)` u `auth_hash`
  (`BCryptPasswordEncoder`), nikad authKey ni master lozinku. Kripto blobovi (`enc_usk`,
  `enc_private_key`, `public_key`) se dekodiraju iz base64 i upisuju kao `bytea` —
  neprozirni za server.
- **Bean Validation** (`spring-boot-starter-validation`) — kastom constraint
  `@Base64Bytes(min,max)` (`common/validation/`) proverava da je svaki artefakt validan
  base64 očekivane veličine (salt 16B, authKey 32B, encUsk 60B, publicKey ~294B,
  encPrivateKey 1230–1300B). Donja granica `encPrivateKey` je IZNAD veličine nešifrovanog
  PKCS8 (1217B) → odbija slučajno poslat plaintext privatni ključ. `kdfIterations ≥ 600000`.
  Jackson `fail-on-unknown-properties=true` → nepoznata polja (npr. „masterPassword") = `400`.
- **`BCryptPasswordEncoder` bean** (`config/SecurityConfig`) — samo `spring-security-crypto`
  (bez punog security starter-a / filter chain-a; to dolazi u Fazi 4), pa je `/users/register`
  otvoren bez dodatne security konfiguracije.
- **Tipizovane greške + `GlobalExceptionHandler`** (`common/error/`) — `AppException` baza +
  `ConflictException` (409); mapiranje u `{ "error": { "code", "message" } }` bez internih
  detalja. `409 CONFLICT` za zauzeto korisničko ime/email, `400 VALIDATION`/`BAD_REQUEST`.
- **Audit stub** (`audit/service/AuditService`) — `record(...)` upisuje `USER_REGISTERED`
  zapis sa `prevHash="GENESIS"` i jedinstvenim SHA-256 hešom (kolona `hash` je UNIQUE).
  Pravi linearni hash-lanac + `verifyChain()` + anchoring dolaze u Fazi 11.
- **Frontend `features/auth`** — `RegisterForm` (kebab `register-form.tsx`): unos
  username/email/master lozinka (+ potvrda, min 12), zove `bootstrapKeys(pw)` (kripto na
  klijentu), serijalizuje artefakte i POST-uje. `registration.ts` (`buildRegisterRequest`,
  čista funkcija — bez lozinke u izlazu), `api/codec.ts` (base64 ↔ bajtovi, standardni
  format koji `java.util.Base64` strogi dekoder prihvata), `api/client.ts` (axios ka
  `${gateway}/api`, `withCredentials`). React Router: `/` (health), `/register`.

**Acceptance Criteria:**
- [x] `POST /users/register` vraća `201`; u DB `auth_hash` ≠ poslati `authKey`.
  *(`UserRegistrationTest`: `auth_hash` počinje sa `$2`, `≠ authKey`, a
  `passwordEncoder.matches(authKey, auth_hash)` = true.)*
- [x] `enc_usk`, `enc_private_key`, `public_key` upisani kao `bytea`, ne-prazni.
  *(`UserRegistrationTest`: `encUsk` 60B, ostali ne-prazni; `kdfSalt` 16B, `kdfIterations` 600000.)*
- [x] Ne postoji kolona sa plaintext lozinkom/USK/privatnim ključem. *(Server prima samo
  šifrovane artefakte + `authKey`; čuva `bcrypt(authKey)` i klijentske šifrate; nema
  password kolone. Negativan test: `encPrivateKey` veličine plaintext PKCS8 → `400`;
  nepoznato polje `masterPassword` → `400` i nalog se ne kreira.)*

**Verifikacija (lokalno, hand-installed JDK 21 + Maven 3.9.9 — bez Dockera):**
- `mvn -f backend/pom.xml test` → **BUILD SUCCESS, 11 testova, 0 grešaka** (4 nova u
  `UserRegistrationTest`, `@SpringBootTest` + MockMvc nad embedded PG16).
- `npm test` (`frontend/`) → **7 test fajlova, 18 testova, 0 grešaka** (5 novih:
  `codec.test.ts`, `registration.test.ts` — uklj. „telo NE sadrži master lozinku").
- `npm run build` (`tsc && vite build`) → čist type-check + build.

---

## Faza 4 — Autentikacija (lozinka + MFA + sesije)

**Šta je urađeno:**
- **Pun Spring Security filter chain** (`spring-boot-starter-security`) — stateless, token-based:
  autentikacija se nosi access JWT-om u `sv_access` **HttpOnly** kolačiću
  (`security/JwtCookieAuthenticationFilter`, instanciran u `config/SecurityConfig`, NIJE bean
  da ga Boot ne auto-registruje kao samostalni servlet filter). CSRF isključen (kolačići su
  `SameSite=Strict`). Javne rute: `/users/register`, `/auth/login/**`, `/auth/totp/**`,
  `/auth/refresh`; sve ostalo (`/auth/me`, buduće) traži važeći access token.
  `security/RestAuthenticationEntryPoint` vraća konzistentan `{error:{code,message}}` za 401/403.
- **JWT (jjwt 0.12.x)** — `security/JwtService`: tri tipa tokena (`access` nosi username+role;
  `refresh` nosi `sxp` = apsolutni cap sesije; `mfa` privremeni tiket). HS256 (tajna iz
  `app.auth.jwt-secret`), svaki token ima `jti` (jedinstven → SHA-256 heš refresh-a ne kolidira).
  `parseAllowingExpired` čita `sxp` i kad je token istekao (radi jasnog `SESSION_EXPIRED`).
- **TOTP (dev.samstevens.totp 1.7.x)** — `auth/service/TotpService`: generiše base32 tajnu,
  `otpauth://` URI + PNG QR (data URI), verifikuje 6-cifreni kod (RFC 6238). Tajna se čuva
  šifrovana server-side (`auth/service/ServerSecretCipher`, AES-256-GCM, ključ = `SHA-256(SERVER_KMS_KEY)`)
  u `users.totp_secret_enc` — auth materijal van zero-knowledge domena.
- **Login tok** (`auth/service/AuthService` + `auth/web/AuthController`, prefiks `/auth`):
  - `POST /auth/login/params` `{username}` → `{kdfSalt, kdfIterations}` (klijent izvede `authKey`;
    za nepostojeći nalog deterministički pseudo-salt → otpornost na enumeraciju).
  - `POST /auth/login/step1` `{username, authKey}` → bcrypt provera; `403` ako nalog nije `ACTIVE`;
    izdaje `mfaTicket` (+ `totpEnabled` flag).
  - `POST /auth/totp/setup` `{mfaTicket}` → otpauth URI + QR (tajna „pending" do verifikacije).
  - `POST /auth/totp/verify` `{mfaTicket, totpCode}` → uključuje `totp_enabled`.
  - `POST /auth/login/step2` `{mfaTicket, totpCode}` → verifikuje TOTP, izdaje access+refresh
    (`auth/service/TokenService`), postavlja oba kolačića `HttpOnly; Secure; SameSite=Strict`,
    vraća `VaultMaterial` (šifrovani `encUsk/encPrivateKey/kdfSalt/...`) za klijentsko otključavanje.
  - `POST /auth/refresh` → rotacija: stari refresh `revoked` u `refresh_token` (heš), nov par;
    istek novog = `min(now+refresh_token_ttl_sec, session_expires_at)`; posle apsolutnog capa
    (`session_max_ttl_sec` od logina) → `401 SESSION_EXPIRED`. TTL-ovi se čitaju iz aktivne
    `security_policy` (admin ih menja u Fazi 8).
  - `GET /auth/me` → metapodaci naloga (zaštićeno access tokenom).
- **Frontend** — `context/session-context.tsx` (React Context; otključani `usk`+privatni ključ
  žive SAMO u memoriji, nikad u localStorage/sessionStorage → refresh stranice = ponovni unlock).
  `crypto/vault.ts` `deriveLoginAuthKey`; `features/auth/login.ts` (`computeAuthKey`, `unlockVault` —
  čiste funkcije), `features/auth/api.ts` (params/step1/totp/step2/refresh/me), multi-step
  `features/auth/login-form.tsx` (credentials → TOTP setup/QR → unos koda → otključavanje).
  Ruta `/login`, `SessionProvider` u `main.tsx`.

**Acceptance Criteria:**
- [x] Login bez validnog TOTP-a → `401`. *(`AuthFlowTest.loginBezValidnogTotpVraca401`: pogrešan
  kod → `401`, bez `Set-Cookie`; `pogresnaLozinkaVraca401`: pogrešan authKey → `401`.)*
- [x] Pun tok (step1→TOTP→step2) postavlja 2 kolačića sa ispravnim flegovima.
  *(`punTokSesijePostavljaDvaKolacicaSaIspravnimFlegovima`: 2 `Set-Cookie`, oba sadrže
  `HttpOnly`, `Secure`, `SameSite=Strict`; potom `/auth/me` sa kolačićem → `200`, bez → `401`.)*
- [x] Posle `access_token_ttl_sec` zaštićeni endpoint → `401`; `/auth/refresh` izda nov access;
  stari refresh više ne radi. *(`posleIstekaAccessTokenaMeVraca401PaRefreshIzdajeNov` +
  `rotacijaRefreshTokenaPonistavaStari`: ponovna upotreba starog refresh-a → `401`.)*
- [x] Posle `session_max_ttl_sec` od logina `/auth/refresh` → `401` (apsolutni cap; refresh TTL
  je 3600 ali sesija 1s → jedino cap obara refresh). *(`posleApsolutnogCapaSesijeRefreshVraca401`.)*
- [x] E2E: posle login-a frontend otključa i drži USK u memoriji (ne u storage-u).
  *(`login.test.ts`: `computeAuthKey` reprodukuje isti `authKey` koji server čuva, `unlockVault`
  rekonstruiše IDENTIČAN USK iz vraćenog materijala, pogrešna lozinka ne otključava;
  `SessionContext` drži ključeve u React state-u — nigde u kodu nema localStorage/sessionStorage.)*

**Verifikacija (lokalno, hand-installed JDK 21 + Maven 3.9.9 — bez Dockera):**
- `mvn -f backend/pom.xml test` → **BUILD SUCCESS, 18 testova, 0 grešaka** (7 novih u
  `AuthFlowTest`, `@SpringBootTest` + MockMvc nad embedded PG16; `HealthControllerTest` ažuriran
  da učita stvarni security chain).
- `npm test` (`frontend/`) → **8 test fajlova, 21 test, 0 grešaka** (3 nova u `login.test.ts`).
- `npm run build` (`tsc && vite build`) → čist type-check + build.

> Napomena: `app.auth.cookie-secure` je u dev-u `false` (http://localhost); u produkciji/HTTPS
> se pali preko `APP_COOKIE_SECURE=true`. Test forsira `true` da proveri `Secure` flag.
