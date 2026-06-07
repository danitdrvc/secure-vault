# PROGRESS — Secure Vault

Status implementacije po fazama (vidi `DEVELOPMENT_PLAN.md`).

- [x] Faza 0  — Setup i Konfiguracija
- [x] Faza 1  — Data Layer i Migracije
- [x] Faza 2  — Klijentski Kripto Sloj
- [x] Faza 3  — Registracija i Skladištenje Ključeva
- [x] Faza 4  — Autentikacija (lozinka + MFA + sesije)
- [x] Faza 5  — OIDC Prijava
- [x] Faza 6  — Vault CRUD
- [x] Faza 7  — Sigurno Deljenje
- [x] Faza 8  — Admin i Sigurnosne Politike
- [ ] Faza 9  — API Gateway i Rate Limiting
- [ ] Faza 10 — Honeypot i Honeytokens
- [ ] Faza 11 — Imutable Audit Log
- [ ] Faza 12 — Integracija i Hardening (Dockerizacija preskočena)

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

---

## Faza 5 — OIDC Prijava

**Šta je urađeno:**
- **Manualni OIDC authorization-code tok** (NE `oauth2Login` filter — ostajemo stateless sa
  sopstvenim JWT kolačićima iz Faze 4). Donet je `spring-security-oauth2-jose` SAMO radi
  Nimbus dekodera i OAuth2 validatora za proveru `id_token`-a.
- **`config/OidcProperties`** (`app.oidc.*`, registrovan u `SecurityConfig`): `enabled`
  (default `false` → `/auth/oidc/**` vraća `404`), `issuer`, `client-id/secret`,
  `authorization-uri`, `token-uri`, `jwks-uri`, `redirect-uri`, `scopes`,
  `post-login-redirect-uri`/`post-login-error-uri`, `state-ttl-sec`. Sve iz env-a
  (`application.yml` + `.env.example` placeholderi).
- **`auth/oidc/OidcAuthenticator`** (seam) — `authenticate(code, expectedNonce) → OidcIdentity`.
  Produkcioni `HttpOidcAuthenticator`: razmena code-a na token endpointu (`RestClient`),
  verifikacija `id_token`-a Nimbus dekoderom protiv JWKS-a (potpis + issuer + audience=client_id
  + timestamp) i provera `nonce`. JWKS dekoder se gradi lenjivo (dok je OIDC isključen, bean
  postoji ali ne dotiče mrežu). Vraća samo `sub` (+`email`) — NIKAD kripto materijal.
- **`auth/oidc/OidcService`** — `start()` gradi authorization redirect URL + potpisani
  state/nonce token (`JwtService.issueOidcState`, novi `typ=oidc_state`); `callback()` validira
  state (CSRF: query `state` mora da odgovara potpisanom u kolačiću), verifikuje `id_token`,
  mapira identitet na nalog, proverava `ACTIVE`, pa izdaje sesiju preko `TokenService.issueForLogin`
  (isti par kolačića kao Faza 4). Svaki neuspeh → redirect na frontend error URL, bez sesijskih
  kolačića i bez internih detalja.
- **Mapiranje/povezivanje naloga** (`OidcService.resolveUser`) — prvo po `users.oidc_subject`
  (već povezan nalog). Ako nema, pri PRVOJ prijavi povezuje po **verifikovanom email-u**
  (`email_verified`): nalog sa istim email-om koji još nema `oidc_subject` se trajno poveže sa
  Google `sub`. Bezbedno: provajder je potvrdio email, a OIDC sesija i dalje NE otključava vault
  (master lozinka obavezna). Nalog koji već ima DRUGI `oidc_subject` se ne preuzima.
- **`auth/web/OidcController`** — `GET /auth/oidc/start` (`302` + `sv_oidc_state` kolačić) i
  `GET /auth/oidc/callback` (`302` na frontend; na uspeh postavlja `sv_access`+`sv_refresh`,
  uvek poništava state kolačić). `AuthCookieFactory`: `sv_oidc_state` je **`SameSite=Lax`**
  (NE Strict) — da preživi cross-site redirect sa provajdera; sesijski kolačići ostaju Strict.
- **Zero-knowledge očuvan:** OIDC callback NE vraća vault materijal. Dodat zaštićeni
  `GET /auth/vault-material` (`AuthService.vaultMaterial`) koji vraća SAMO šifrat
  (`encUsk/encPrivateKey/...`); klijent ga dohvati posle OIDC sesije i lokalno pozove `unlock`
  master lozinkom. Server i dalje ne vidi nijedan ključ.
- **Frontend** — `features/auth/api.ts`: `oidcStartUrl()` (full-page navigacija, ne XHR) i
  `fetchVaultMaterial()`. `login-form.tsx`: dugme „Prijava preko eksternog naloga (OIDC)" u
  credentials fazi; po povratku (`/login?oidc=success`) nova `oidc-unlock` faza traži master
  lozinku → `fetchMe` + `fetchVaultMaterial` → `unlockVault` → upis u memorijsku sesiju
  (`oidc=error` prikazuje grešku; query param se čisti da refresh ne ponovi tok).

**Acceptance Criteria:**
- [x] Uspešan callback kreira sesiju i kolačiće kao u Fazi 4. *(`OidcFlowTest
  .uspesanCallbackPostavljaSesijuAliNeVracaVaultMaterijal`: `302` na success URL, `sv_access`
  + `sv_refresh` sa `HttpOnly`/`Secure`/`SameSite=Strict`, potom `/auth/me` sa access
  kolačićem → `200`. `startPreusmeravaNaProvajdera...`: `302` na authorization URL +
  `sv_oidc_state` `SameSite=Lax`. Negativni: nepovezan `sub` i nevažeći `state` → redirect na
  error URL bez sesijskih kolačića.)*
- [x] Posle OIDC logina vault je i dalje „locked" dok se ne unese master lozinka. *(Isti test:
  callback odgovor NE sadrži `encUsk`/`encPrivateKey`; materijal se dobija tek posebnim
  `GET /auth/vault-material`. Frontend `oidc.test.ts`: bez tačne master lozinke materijal se ne
  otključava (`unlockVault` baca), a sa lozinkom rekonstruiše IDENTIČAN USK.)*

**Verifikacija (lokalno, hand-installed JDK 21 + Maven 3.9.9 — bez Dockera):**
- `mvn -f backend/pom.xml test` → **BUILD SUCCESS, 22 testa, 0 grešaka** (4 nova u `OidcFlowTest`,
  `@SpringBootTest` + MockMvc nad embedded PG16; `OidcAuthenticator` zamenjen stubom — bez živog
  provajdera).
- `npm test` (`frontend/`) → **9 test fajlova, 23 testa, 0 grešaka** (2 nova u `oidc.test.ts`).
- `npm run build` (`tsc && vite build`) → čist type-check + build.

> Napomena: `app.oidc.enabled=false` podrazumevano → `/auth/oidc/**` je `404` dok admin ne
> konfiguriše provajdera (env `OIDC_*`). Povezivanje naloga sa `oidc_subject` je van OIDC toka
> (OIDC ovde samo prijavljuje već povezane naloge).

---

## Faza 6 — Vault CRUD

**Šta je urađeno:**
- **Backend `vault` modul** (`web/` + `service/`, nad postojećim `domain/`+`repository/` iz Faze 1).
  Prefiks `/vault/secrets`; sve rute zahtevaju važeću sesiju (`SecurityConfig` već ima
  `anyRequest().authenticated()`), a identitet dolazi iz access tokena (`@AuthenticationPrincipal
  AuthenticatedUser`), NIKAD iz tela. Server vidi/skladišti isključivo šifrat — enkripcija je
  klijentska.
  - `POST /vault/secrets` `{name, encryptedBlob, wrappedSecretKey}` → `201` + `SecretSummaryResponse`.
    Upisuje `secrets` red (`is_honeytoken=false`) + vlasnikov `secret_access` red
    (`wrapped_secret_key`, `granted_by_id=owner`).
  - `GET /vault/secrets` → metapodaci svih PRISTUPAČNIH tajni bez honeytokena
    (`SecretRepository.findAccessibleNonHoneytoken` — theta-join `Secret`×`SecretAccess` po
    `user_id`; pokriva vlasnika danas i primaoce od Faze 7). Vraća samo `id/name/created/updated`,
    NE blob.
  - `GET /vault/secrets/{id}` → `SecretDetailResponse` (blob + MOJ `wrappedSecretKey` iz mog
    `secret_access` reda). Bez pristupnog reda → `403 FORBIDDEN`; honeytoken/nepostojeće → `404`.
  - `PUT /vault/secrets/{id}` `{name, encryptedBlob}` → samo vlasnik; `secretKey` se NE menja
    (klijent re-šifruje istim ključem) pa `wrapped_secret_key` ostaje važeći.
  - `DELETE /vault/secrets/{id}` → `204`; samo vlasnik; briše i sve `secret_access` redove.
- **Validacija (`@Base64Bytes`)** — `encryptedBlob` 28 B–64 KiB (AES-GCM: nonce(12)+ct+tag(16));
  `wrappedSecretKey` tačno 256 B (RSA-OAEP-2048). `name` `@NotBlank @Size(max=255)`.
- **Honeytokeni nevidljivi** — lista ih izostavlja; direktan `GET /{id}` honeytokena vraća `404`
  (kao da ne postoji), čak i uz postojeći pristupni red. Pravi okidač (freeze + alarm) je Faza 10.
- **Audit stub** — `SECRET_CREATED` / `SECRET_UPDATED` / `SECRET_DELETED` (pravi lanac = Faza 11).
- **`GlobalExceptionHandler`** — dodat `MethodArgumentTypeMismatchException` → `400` (neispravan UUID
  u putanji ne curi kao `500`).
- **Frontend `features/vault`** — `vault-crypto.ts` (čiste fn, bez mreže): `encryptNewSecret`
  (generiše slučajan `secretKey`, `AES-GCM(secretKey, plaintext)`, `wrapTo(mojPublicKey,
  secretKey)`), `decryptSecret` (`unwrap(mojPrivateKey)` → `AES-GCM` dekripcija), `reencryptSecret`
  (re-šifruj izmenu ISTIM ključem, wrap netaknut). `api.ts` (CRUD pozivi). `vault-page.tsx`
  (ruta `/vault`): lista, kreiranje, „Prikaži" (dekripcija u memoriji), izmena, brisanje; bez
  otključanog vault-a stranica traži prijavu.
- **Sopstveni javni ključ u sesiji** — `crypto/vault.ts` novi tip `VaultKeys = UnlockedVault &
  { publicKey }`; `unlockVault` (login.ts) sada uvozi SPKI iz vault materijala i puni `publicKey`,
  pa `SessionContext` drži usk+privateKey+publicKey (sve samo u memoriji). Time klijent može da
  uvije `secretKey` ka sebi bez dodatnog dohvata.

**Acceptance Criteria:**
- [x] Create→Read round-trip vraća identičan plaintext u browseru. *(`vault.test.ts`:
  `encryptNewSecret`→`decryptSecret` = isti plaintext; backend `VaultCrudTest
  .createReadRoundTripVracaNetaknutSifrat`: `encryptedBlob`/`wrappedSecretKey` se vraćaju
  bajt-za-bajt; DB inspekcija: `encrypted_blob` == poslati bajtovi, neprozirno.)*
- [x] DB inspekcija: `encrypted_blob` je nečitljiv; nijedan endpoint ne vraća plaintext.
  *(`VaultCrudTest`: odgovor nema `plaintext` polje; `vault.test.ts`: `encryptedBlob` ne sadrži
  plaintext, `wrappedSecretKey` = 256 B.)*
- [x] `GET /vault/secrets` NIKAD ne vraća honeytoken redove. *(`listaNikadNeVracaHoneytokene`:
  ubačen honeytoken sa pristupnim redom — lista ga ne sadrži, direktan `GET` → `404`.)*
- [x] Korisnik bez pristupa dobija `403` na `GET /vault/secrets/:id`.
  *(`korisnikBezPristupaDobija403`; dodatno `neVlasnikNeMozeDaMenjaNitiBrise` → `403` na PUT/DELETE;
  `neautentikovanPristupVraca401` → `401` bez sesije.)*

**Verifikacija (lokalno, hand-installed JDK 21 + Maven 3.9.9 — bez Dockera):**
- `mvn -f backend/pom.xml test` → **BUILD SUCCESS, 30 testova, 0 grešaka** (7 novih u `VaultCrudTest`,
  `@SpringBootTest` + MockMvc nad embedded PG16).
- `npm test` (`frontend/`) → **10 test fajlova, 27 testova, 0 grešaka** (4 nova u `vault.test.ts`).
- `npm run build` (`tsc && vite build`) → čist type-check + build.

> Napomena: `encryptedBlob` gornja granica (64 KiB) pokriva i veće tajne (npr. sertifikate).
> Rotacija samog `secretKey`-a (nov ključ + re-wrap ka svim primaocima) je tema Faze 8; ovde se
> izmena radi istim ključem da deljenje iz Faze 7 ostane konzistentno.

---

## Faza 7 — Sigurno Deljenje (envelope)

**Šta je urađeno:**
- **Backend `GET /users/{id}/public-key`** (`UserController` → `UserService.getPublicKey`) —
  vraća SPKI javni ključ korisnika (base64) + `userId`. Zahteva važeću sesiju (samo
  `/users/register` je javno). Javni ključ je po prirodi javan; nijedan privatni materijal se
  ne otkriva. Nepostojeći korisnik → `404 NOT_FOUND`. Novi DTO `PublicKeyResponse`.
- **Backend `POST /vault/secrets/{id}/share`** (`VaultController.share` → `VaultService.share`) —
  envelope re-wrap deljenje. Telo `{recipientId, wrappedSecretKey}` (`ShareSecretRequest`:
  `recipientId` `@NotNull`, `wrappedSecretKey` `@Base64Bytes(256,256)` — RSA-OAEP-2048 šifrat).
  Logika: tajna mora biti vidljiva (honeytoken/nepostojeća → `404`); onaj ko deli MORA imati
  svoj `secret_access` red (inače `403` — bez pristupa nema `secretKey`); primalac mora postojati
  (`404`); već podeljeno istom korisniku → `409 CONFLICT` (uz `unique(secret_id,user_id)`).
  Kreira nov `secret_access` red (`wrapped_secret_key` = uvijen ka primaocu, `granted_by_id` =
  onaj ko deli). **`encrypted_blob` se NE dira** (veliki blob se nikad ne re-šifruje). Audit stub
  `SECRET_SHARED`. Vraća `ShareResponse` (samo metapodaci).
- **Autorizacija po ulozi** — `@PreAuthorize("hasRole('TEAM_LEAD')")` na `share` endpointu;
  `@EnableMethodSecurity` u `SecurityConfig`. `Developer` koji pokuša deljenje → `403` PRE ulaska
  u servis. Authority `ROLE_TEAM_LEAD` postavlja `JwtCookieAuthenticationFilter` iz uloge u
  access tokenu.
- **`GlobalExceptionHandler`** — dodat `@ExceptionHandler(AccessDeniedException.class)` → `403`
  `FORBIDDEN` u istom JSON obliku. (Method-security baca `AccessDeniedException` TOKOM poziva
  kontrolera, pa je hvata advice; URL-bazirana odbijanja i dalje obrađuje
  `RestAuthenticationEntryPoint` na nivou filtera — oba daju isti oblik.)
- **Frontend `vault-crypto.ts`** — nova čista (bez mreže) fn `rewrapSecretForRecipient(
  mojWrappedSecretKey, mojPrivateKey, recipientPublicKey)`: otvori `secretKey` svojim privatnim
  ključem i ponovo ga uvije ka javnom ključu primaoca; `encryptedBlob` se ne dira. Plaintext
  `secretKey` nikad ne napušta čitač.
- **Frontend `features/vault/api.ts`** — `getUserPublicKey(userId)` (`/users/{id}/public-key`) i
  `shareSecret(id, {recipientId, wrappedSecretKey})` + tipovi `PublicKeyResponse`/`ShareSecretRequest`/
  `ShareResponse`.
- **Frontend `vault-page.tsx`** — dugme „Podeli" (vidljivo SAMO ako je `session.user.role ===
  'TEAM_LEAD'`) + forma za unos ID-a primaoca. Tok: `getSecret` (moj wrap) → `getUserPublicKey` →
  `importPublicKey` → `rewrapSecretForRecipient` → `shareSecret`. Server forsira ulogu nezavisno
  od UI-ja.

**Acceptance Criteria:**
- [x] Posle deljenja B dekriptuje istu tajnu; `encrypted_blob` je NEPROMENJEN. *(Frontend
  `vault.test.ts` „posle deljenja PRIMALAC dešifruje istu tajnu; blob NEPROMENJEN": Alice uvije
  ka Bobu, Bob dešifruje IDENTIČAN plaintext iz nepromenjenog bloba. Backend `SecretSharingTest
  .teamLeadDeliTajnuPrimalacDobijaSvojWrappedKey`: bajt-za-bajt poređenje `encrypted_blob` pre/posle
  share = isti; primalac kroz `GET` dobija SVOJ wrapped key i tajna se pojavljuje u njegovoj listi.)*
- [x] `Developer` koji pokuša share → `403`. *(`SecretSharingTest.developerNeMozeDaDeli`: `403
  FORBIDDEN`, pristupni red se NE kreira. Dodatno `teamLeadBezPristupaTajniNeMozeDaDeli`: Team Lead
  bez pristupa tuđoj tajni → `403`.)*
- [x] DB: `wrapped_secret_key` za A i B se razlikuju; nijedan nije plaintext. *(`SecretSharingTest`:
  primaočev `wrapped_secret_key` == poslati bajtovi i `≠` vlasnikov; frontend „wrappedSecretKey za
  Alice i Boba se razlikuju; nijedan nije plaintext (256B)" + „tuđi privatni ključ ne čita re-wrap".)*

**Dodatni testovi:** `getPublicKeyVracaJavniKljuc` (SPKI iz DB), `getPublicKeyBezSesijeVraca401`,
`deljenjeIstomKorisnikuDvaputVraca409`, `nepostojeciPrimalacVraca404`.

**Verifikacija (lokalno, hand-installed JDK 21 + Maven 3.9.9 — bez Dockera):**
- `mvn -f backend/pom.xml test` → **BUILD SUCCESS, 37 testova, 0 grešaka** (7 novih u
  `SecretSharingTest`, `@SpringBootTest` + MockMvc nad embedded PG16).
- `npm test` (`frontend/`) → **10 test fajlova, 30 testova, 0 grešaka** (3 nova u `vault.test.ts`).
- `npm run build` (`tsc && vite build`) → čist type-check + build.

> Napomena: deljenje ide po `recipientId` (UUID) — UI ima polje za ID primaoca. Lookup po
> korisničkom imenu i opoziv pristupa (revoke) nisu deo Faze 7; admin upravljanje ulogama dolazi
> u Fazi 8 (ovde se uloga `TEAM_LEAD` u testovima postavlja direktno u repozitorijumu).

---

## Faza 8 — Admin i Sigurnosne Politike

**Šta je urađeno:**
- **Backend admin nalozi** — `PATCH /admin/users/{id}/status` (`AdminUserController` → `UserService
  .updateStatus`). SAMO uloga `ADMIN` (`@PreAuthorize("hasRole('ADMIN')")` na kontroleru). Admin
  aktivira/deaktivira nalog; dozvoljene ciljne vrednosti su SAMO `ACTIVE`/`DEACTIVATED` (`FROZEN` je
  rezervisan za honeypot okidač iz Faze 10 → `400 VALIDATION` ako se pošalje). Deaktivacija odmah
  zaustavlja login (postojeća provera u `AuthService.step1` vraća `403` za svaki status ≠ `ACTIVE`).
  Audit stub `USER_STATUS_CHANGED`. Novi DTO-i `UpdateUserStatusRequest`/`AdminUserResponse`.
- **Backend sigurnosna politika** (`policy` modul: `web/` + `service/`, nad postojećim `domain/`+
  `repository/` iz Faze 1):
  - `GET /policy` — klijentski podskup (`ClientPolicyResponse`: `minMasterPwLength`,
    `defaultRotationDays`); svaka važeća sesija. Klijent njime vodi scenario „povećana min dužina".
  - `GET /admin/policy`, `PATCH /admin/policy` — pun pregled/izmena (`PolicyResponse`); SAMO `ADMIN`.
    PATCH je parcijalan (`UpdatePolicyRequest`, sva polja opciona → menja samo ne-null). „Trajanje
    sesije" se izlaže kao `sessionMaxTtlSec` (apsolutni cap), uz zasebne `accessTokenTtlSec` (prozor
    rotacije) i `refreshTokenTtlSec`. TTL-ove iz politike `TokenService` čita u runtime-u → izmena
    odmah utiče na sledeće tokene. Audit stub `POLICY_UPDATED`.
- **Backend promena master lozinke** — `POST /auth/rotate-master` (`AuthController` → `AuthService
  .rotateMaster`). Zahteva važeću sesiju + step-up dokaz STARE lozinke (`currentAuthKey`, poredi se
  sa `bcrypt(auth_hash)`; mismatch → `401`). Server zameni `auth_hash`, KDF parametre i re-šifrovane
  `encUsk`/`encPrivateKey`; **USK ostaje isti → svi postojeći blobovi tajni i deljenja rade i sa
  novom lozinkom**. Sesijski kolačići se NE menjaju. Audit stub `MASTER_ROTATED`. DTO
  `RotateMasterRequest` (`@Base64Bytes` veličine kao registracija).
- **Backend rotacija tajne** — `POST /vault/secrets/{id}/rotate` + `GET /vault/secrets/{id}/access`
  (`VaultController` → `VaultService.rotate`/`listAccess`, oba vlasnik-only). Rotacija: nov blob +
  re-wrap ka SVIM postojećim primaocima; `wrappedKeys` mora pokriti TAČNO skup `secret_access` redova
  (manjak/višak → `400 VALIDATION`). Upisuje novi blob, osvežava `rotated_at`, menja `wrapped_secret_key`
  svakom primaocu — stara `wrapped_secret_key` time prestaje da otvara novi blob. Audit `SECRET_ROTATED`.
  DTO `RotateSecretRequest` (+ `WrappedKeyEntry`), `SecretAccessResponse`.
- **Rok rotacije (metapodaci)** — `secrets.rotation_days`/`rotated_at` (iz Faze 1) sada izloženi:
  `CreateSecretRequest` prima opcioni `rotationDays`; `SecretDetailResponse` vraća `rotationDays`+
  `rotatedAt`. Server NE okida rotaciju automatski (zero-knowledge) — odluku donosi klijent pri
  otvaranju tajne.
- **Tipizovana greška** — nova `common/error/ValidationException` (`400 VALIDATION`) za poslovne
  invarijante (npr. nepotpun re-wrap, nedozvoljen status); `GlobalExceptionHandler` je već mapira
  preko `AppException` baze.
- **Frontend kripto** (čiste fn, bez mreže):
  - `crypto/vault.ts` `rotateMasterKey(stara, nova, ...)` → otključa stari KEK/USK, izvede nov KEK/
    authKey iz nove lozinke (svež salt) i re-šifruje `encUsk` (nov KEK) + `encPrivateKey` (isti USK,
    svež nonce). Vraća `MasterRotationArtifacts` (+ `currentAuthKey` kao dokaz stare lozinke).
  - `features/vault/vault-crypto.ts` `rotateSecret(plaintext, recipients)` → nov slučajan `secretKey`,
    re-šifrovan blob, uvijanje ka javnom ključu SVAKOG primaoca.
  - `features/vault/rotation.ts` `isRotationDue(rotatedAt, rotationDays, now)` — `null`/`≤0`/nevažeći
    datum → `false`; inače istekao kad je `rotatedAt + rotationDays` u prošlosti.
  - `features/auth/master-rotation.ts` `buildRotateMasterRequest` (sastavi base64 telo iz materijala).
- **Frontend UI** — `features/admin/admin-page.tsx` (ruta `/admin`, samo `ADMIN`): status naloga +
  editor politike (`features/admin/api.ts`). `features/auth/change-master-form.tsx` (ruta `/account`):
  scenario „povećana min dužina" — dohvati `GET /policy`, upozori ako je trenutna lozinka kraća, pa
  lokalno re-šifruje i pošalje. `vault-page.tsx`: opcioni „Rok rotacije (dani)" pri kreiranju; pri
  otvaranju tajne `isRotationDue` prikaže upozorenje („Tajna je istekla — preporučena rotacija") +
  „Rotiraj sada" (dohvati access listu → javne ključeve → `rotateSecret` → `POST .../rotate`).

**Acceptance Criteria:**
- [x] Deaktiviran korisnik ne može da se uloguje (`403` u step1). *(`AdminPolicyTest
  .adminDeaktiviraNalogKojiViseNeMozeDaSeUloguje`: admin PATCH → `DEACTIVATED`, dev step1 → `403`;
  reaktivacija → step1 ponovo prolazi. `developerNeMozeDaMenjaStatus`/`developerNeMozeAdminPolicy`:
  ne-admin → `403`; `adminNeMozePostavitiFrozen` → `400`.)*
- [x] Posle `rotate-master`, login NOVOM lozinkom otključava sve postojeće tajne (blobovi netaknuti).
  *(Frontend `master-rotation.test.ts`: nova lozinka rekonstruiše IDENTIČAN USK, stara ne otključava,
  tajna šifrovana PRE promene se otvara privatnim ključem iz unlock-a. Backend `MasterRotationTest
  .rotacijaMenjaAuthIEncUskAliNeDiraTajne`: stari authKey → `401`, novi → `200`, `enc_usk` promenjen,
  `encrypted_blob` tajne bajt-za-bajt NETAKNUT; `pogresnaTrenutnaLozinkaOdbijaRotaciju` → `401`.)*
- [x] Otvaranje tajne čiji je `rotated_at + rotation_days` u prošlosti prikazuje upozorenje; `null`/
  nevažeći rok ga NE prikazuje. *(`rotation.test.ts`: istekla/granica → `true`; `null`/`0`/negativan/
  nevažeći datum → `false`. UI: `vault-page.tsx` `isRotationDue` puni `open.rotationDue` →
  `rotation-warning-{id}` + „Rotiraj sada".)*
- [x] Rotacija tajne: stara `wrapped_secret_key` više ne otvara novi blob; nova otvara.
  *(`vault.test.ts` „NOVA wrapped otvara nov blob; STARA wrapped ga više ne otvara" + re-wrap ka više
  primaoca. Backend `SecretRotationTest.vlasnikRotiraTajnuBlobIWrappedSeMenjaju`: blob i
  `wrapped_secret_key` se menjaju, `rotated_at` osvežen; `rotacijaMoraReWrapovatiSvePrimaoce`:
  nepotpun re-wrap → `400`; `neVlasnikNeMozeDaRotiraNitiVidiAccess` → `403`.)*

**Verifikacija (lokalno, hand-installed JDK 21 + Maven 3.9.9 — bez Dockera):**
- `mvn -f backend/pom.xml test` → **BUILD SUCCESS, 51 testa, 0 grešaka** (14 novih: `AdminPolicyTest` 7,
  `MasterRotationTest` 3, `SecretRotationTest` 4; `@SpringBootTest` + MockMvc nad embedded PG16).
- `npm test` (`frontend/`) → **12 test fajlova, 42 testa, 0 grešaka** (12 novih: `rotation.test.ts` 6,
  `master-rotation.test.ts` 4, `vault.test.ts` +2).
- `npm run build` (`tsc && vite build`) → čist type-check + build.

> Napomena: rotacija tajne re-wrap-uje SVE primaoce, pa klijent pri rotaciji dohvati `GET
> /vault/secrets/{id}/access` (vlasnik-only) i javne ključeve svih (`/users/{id}/public-key`).
> Promena master lozinke ne dira tajne (USK je nepromenjen), pa nema potrebe za ponovnim loginom.
