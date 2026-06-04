# Secure Vault — DEVELOPMENT_PLAN.md
> Izvor istine (Source of Truth) za inkrementalnu implementaciju.
> Čita se poglavlje po poglavlje: implementiraj fazu → verifikuj kroz Acceptance Criteria → tek onda pređi na sledeću.
> Svaka faza je minimalna i testabilna. Ne preskači verifikaciju.

---

## 1. Pregled Projekta i Tehnološki Stek

### 1.1 Opis i svrha
Secure Vault je sistem za sigurno upravljanje tajnama (lozinke, API ključevi, sertifikati)
zasnovan na **zero-knowledge** arhitekturi. Sva enkripcija i dekripcija dešavaju se **isključivo
u čitaču (klijentu)**. Server u bazu upisuje samo šifrovane blobove, javne ključeve i hešove —
nikada ne vidi master lozinku niti dekriptovani sadržaj tajni.

Sistem prepoznaje tri uloge:
- **Admin** — aktivira/deaktivira naloge i definiše sigurnosne politike (NE upravlja tajnama).
- **Team Lead** — može deliti tajne sa članovima tima (Developer).
- **Developer** — kreira, koristi i prima podeljene tajne.

### 1.2 Tehnološki stek

> Cilj: jednostavni, standardni alati koji se uče na fakultetu. Backend je **Java Spring Boot**.
> Sva kriptografija na klijentu koristi **ugrađeni Web Crypto API** — nijedna eksterna kripto biblioteka.

**Frontend (SPA klijent — zona od poverenja za kripto):**
- React `18` + TypeScript
- Vite (build/dev server)
- React Router (navigacija)
- React Context + hooks (stanje sesije i otključanih ključeva u memoriji)
- `axios` (HTTP klijent ka gateway-u)
- **Web Crypto API (`crypto.subtle`)** — JEDINI kripto sloj:
  - PBKDF2 (derivacija ključa iz master lozinke)
  - HKDF (razdvajanje namena ključeva)
  - AES-256-GCM (simetrična enkripcija tajni i ključeva)
  - RSA-OAEP (asimetrično deljenje — enkripcija ka javnom ključu)
  - SHA-256 (hešovi)
- **Zabrana:** nikada ne pisati sopstvene implementacije kripto algoritama.

**Backend (API server — "slep" na sadržaj):**
- Java `21` (LTS) + Spring Boot `3.3.x`
- Maven (build)
- Spring Web (REST kontroleri)
- Spring Security (autentikacija, autorizacija po ulogama `@PreAuthorize`, OAuth2/OIDC client)
- Spring Data JPA + Hibernate (ORM)
- Flyway (verzionisanje šeme / migracije)
- PostgreSQL JDBC driver
- `io.jsonwebtoken:jjwt` `0.12.x` — access/refresh JWT tokeni
- `dev.samstevens.totp` `1.7.x` — TOTP (drugi faktor) + generisanje QR koda
- Spring Security Crypto (`BCryptPasswordEncoder`) — server-side hash auth materijala
- `jakarta.validation` + Hibernate Validator (validacija DTO)

**API Gateway (zasebni servis — jedina ulazna tačka):**
- Java `21` + Spring Cloud Gateway (reaktivni proxy ka backendu)
- Spring Data Redis (Reactive) — `RedisRateLimiter` (napredni rate limiting)
- Custom `GlobalFilter` (`IpGuardFilter`) — detekcija i blokiranje sumnjivih IP adresa

**Baze i infrastruktura:**
- PostgreSQL `16`
- Redis `7`
- Docker + Docker Compose

**Testiranje:**
- Backend / Gateway: JUnit `5` + Spring Boot Test + MockMvc
- Frontend: Vitest + Testing Library
- (opciono) Testcontainers za integracione testove sa pravim Postgresom

---

## 2. Arhitektura i Dizajnerske Odluke (Design Decisions)

### 2.1 Arhitektonski šablon
Backend koristi **standardnu Spring slojevitu arhitekturu**, organizovanu po funkcionalnim
paketima (package-by-feature). Svaki feature paket ima slojeve:
- `web/` — REST kontroleri, DTO (Request/Response), validacija (Bean Validation).
- `service/` — poslovna logika (use-case orkestracija).
- `repository/` — Spring Data JPA repozitorijumi (interfejsi).
- `domain/` — JPA entiteti i enumi.

Cross-cutting paketi:
- `config/` — `SecurityConfig`, CORS, definicije bean-ova.
- `security/` — JWT filter, `UserDetails`, autorizacioni helperi.
- `common/` — tipizovane greške i globalni `@RestControllerAdvice`.

Pravilo zavisnosti: kontroleri zovu servise; servisi zovu repozitorijume; entiteti ne zavise
od web sloja. Poslovna logika je u `service/`, nikad u kontrolerima.

### 2.2 Organizacija direktorijuma (monorepo)
```
secure-vault/
├── docker-compose.yml
├── .env.example
├── DEVELOPMENT_PLAN.md
├── PROGRESS.md                       # AI ovde čekira završene faze
├── gateway/                          # Spring Cloud Gateway (Maven projekat)
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/securevault/gateway/
│       │   ├── GatewayApplication.java
│       │   ├── config/               # rute, RedisRateLimiter + KeyResolver beans
│       │   └── filter/               # IpGuardFilter (GlobalFilter)
│       └── resources/application.yml
├── backend/                          # Spring Boot (Maven projekat)
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/
│       ├── main/java/com/securevault/
│       │   ├── SecureVaultApplication.java
│       │   ├── auth/      {web,service,repository,domain}/
│       │   ├── user/      {web,service,repository,domain}/
│       │   ├── vault/     {web,service,repository,domain}/
│       │   ├── sharing/   {web,service,repository,domain}/
│       │   ├── policy/    {web,service,repository,domain}/
│       │   ├── audit/     {web,service,repository,domain}/
│       │   ├── honeypot/  {web,service,repository,domain}/
│       │   ├── security/  # JWT filter, UserDetails, guards
│       │   ├── config/    # SecurityConfig, CORS, beans
│       │   └── common/    # greške, GlobalExceptionHandler
│       ├── main/resources/
│       │   ├── application.yml
│       │   └── db/migration/         # Flyway: V1__init.sql, V2__seed.sql, ...
│       └── test/java/com/securevault/ # JUnit testovi po feature-u
└── frontend/                         # React + Vite (npm projekat)
    ├── Dockerfile
    └── src/
        ├── main.tsx
        ├── app/
        ├── crypto/                   # Web Crypto API wrapperi (kdf/derive/sym/asym/vault)
        ├── api/                      # axios klijent ka gateway-u
        ├── context/                  # React Context (session, otključani vault u memoriji)
        ├── features/{auth,vault,sharing,admin}/
        └── components/
```

### 2.3 Ključne dizajnerske odluke i kompromisi

| Odluka | Izbor | Obrazloženje / Trade-off |
|---|---|---|
| Derivacija ključa | PBKDF2-HMAC-SHA256 (klijent, ~600k iteracija) | Ugrađen u Web Crypto API → nula zavisnosti; spec eksplicitno dozvoljava PBKDF2. Trade-off: slabiji od Argon2, kompenzuje se visokim brojem iteracija. |
| Razdvajanje namena | HKDF iz master key-a | Auth materijal i KEK se izvode odvojenim `info` labelama; znanje jednog ne otkriva drugi. |
| KEK sloj (Stretched key) | KEK enkriptuje USK, ne tajne | Promena lozinke re-šifruje samo USK (1 blob), ne sve tajne. Trade-off: jedan indirekcioni sloj više. |
| Radni ključ | Slučajan USK (AES-256), nezavisan od lozinke | USK ne zavisi od lozinke → promena lozinke ne dira tajne. |
| Asimetrija za deljenje | RSA-OAEP 2048 (Web Crypto) | Direktno prati RSA primer iz specifikacije; enkriptuje samo mali `secretKey` (32B) pa nema problema sa RSA limitom veličine. Ugrađen u browser. |
| Envelope enkripcija | Po-tajni `secretKey`; blob se nikad ne re-šifruje | Deljenje uvija samo mali `secretKey` ka primaocu; veliki blob ostaje isti. |
| Auth dokaz | Klijent šalje `authKey`; server čuva `bcrypt(authKey)` | Curenje baze ne otkriva login-kredencijal niti KEK. |
| OIDC vs unlock | OIDC daje samo sesiju, NE ključ | Master lozinka je i dalje obavezna za otključavanje vault-a → zero-knowledge se ne narušava. |
| State management | React Context + hooks | Otključani ključevi žive samo u memoriji (Context state, van localStorage). Trade-off: refresh stranice = ponovni unlock. |
| Sesije | Kratki access JWT (jjwt) + rotirajući refresh; HttpOnly/Secure/SameSite=Strict | Konfigurabilan TTL za test rotacije; refresh hešovan u Redisu. **Admin-definisano "trajanje sesije" = `session_max_ttl_sec`** (apsolutni cap od logina): pri loginu se upamti `session_expires_at = login + session_max_ttl_sec`, a rotacija refresh-a nikad ne izdaje token sa istekom preko te granice → posle isteka sledi obavezan ponovni login bez obzira na aktivnost. `access_token_ttl_sec` je tehnički prozor rotacije; `refresh_token_ttl_sec` je trajanje pojedinačnog refresh tokena. |
| Audit integritet | Linearni hash lanac + external anchoring | Lanac hvata tihu izmenu; anchoring (periodični upis vrha izvan baze) sprečava chain rewrite. Trade-off: jednostavnije od Merkle stabla bez gubitka garancije. |
| Gateway | Spring Cloud Gateway, zaseban servis | Jedina ulazna tačka; rate limiting/IP-blok izolovani od poslovne logike; ostaje u Javi (dosledan stek). |
| TOTP tajna | Čuva se na serveru (šifrovana env ključem) | Verifikacija TOTP-a je server-side → izvan zero-knowledge domena (to je auth, ne vault sadržaj). |

---

## 3. Model Podataka i Šema (Data Layer)

### 3.1 Entiteti i relacije
- **users** 1—N **secrets** (vlasnik).
- **secrets** 1—N **secret_access** (po jedan red za svakog ko ima pristup, uključujući vlasnika; sadrži `wrapped_secret_key`).
- **users** 1—N **secret_access** (kome je dodeljen pristup).
- **security_policy** — jedan aktivan red (org-wide).
- **audit_log** — append-only hash lanac (`prev_hash` → `hash`).
- **audit_anchor** — periodični "sidreni" zapisi vrha lanca.
- **honeytoken** — lažne tajne, nevidljive regularnom API-ju.
- **security_event** — alarmi (honeypot okidač, IP blok, zamrzavanje naloga).
- **refresh_token** — metapodaci rotiranih tokena (hešovani; primarno u Redisu, ogledalo u DB radi audita).

### 3.2 Eksplicitna šema (PostgreSQL DDL — Flyway `V1__init.sql`)
> JPA entiteti se mapiraju na ove tabele (`@Table`, `@Column` u snake_case; `byte[]` ↔ `bytea`;
> enum ↔ `varchar` preko `@Enumerated(EnumType.STRING)`). Hibernate radi sa `ddl-auto=validate` —
> Flyway je vlasnik šeme.

```sql
create extension if not exists "pgcrypto";

create table users (
  id              uuid primary key default gen_random_uuid(),
  username        varchar(64)  not null unique,
  email           varchar(255) not null unique,
  role            varchar(16)  not null default 'DEVELOPER'
                    check (role in ('ADMIN','TEAM_LEAD','DEVELOPER')),
  status          varchar(16)  not null default 'ACTIVE'
                    check (status in ('ACTIVE','FROZEN','DEACTIVATED')),

  -- KDF parametri (klijent ih koristi da reprodukuje master key)
  kdf_salt        bytea        not null,
  kdf_iterations  int          not null default 600000,

  -- Auth: server čuva bcrypt(authKey), NIKAD authKey ni master lozinku
  auth_hash       varchar(100) not null,

  -- Zero-knowledge artefakti (server ih ne može dešifrovati)
  enc_usk         bytea        not null,   -- AES-256-GCM(KEK, USK), uključuje nonce
  public_key      bytea        not null,   -- RSA javni ključ (SPKI, plaintext)
  enc_private_key bytea        not null,   -- AES-256-GCM(USK, privateKey PKCS8), uključuje nonce

  -- MFA / OIDC (izvan zero-knowledge domena)
  totp_secret_enc bytea,                   -- TOTP tajna šifrovana server-side ključem
  totp_enabled    boolean      not null default false,
  oidc_subject    varchar(255) unique,

  created_at      timestamptz  not null default now(),
  updated_at      timestamptz  not null default now()
);
create index idx_users_status on users(status);

create table secrets (
  id             uuid primary key default gen_random_uuid(),
  owner_id       uuid         not null references users(id),
  name           varchar(255) not null,                 -- metapodatak; nije tajni sadržaj
  encrypted_blob bytea        not null,                  -- AES-256-GCM(secretKey, plaintext) + nonce
  is_honeytoken  boolean      not null default false,    -- regularni API filtrira false
  rotation_days  int,                                    -- null = bez rotacije
  rotated_at     timestamptz  not null default now(),
  created_at     timestamptz  not null default now(),
  updated_at     timestamptz  not null default now()
);
create index idx_secrets_owner on secrets(owner_id);
create index idx_secrets_honeytoken on secrets(is_honeytoken);

create table secret_access (
  id                 uuid    primary key default gen_random_uuid(),
  secret_id          uuid    not null references secrets(id) on delete cascade,
  user_id            uuid    not null references users(id),
  -- RSA-OAEP(secretKey, user.public_key) — samo vlasnik privatnog ključa otvara
  wrapped_secret_key bytea   not null,
  granted_by_id      uuid,
  created_at         timestamptz not null default now(),
  unique (secret_id, user_id)
);
create index idx_secret_access_user on secret_access(user_id);

create table security_policy (
  id                    uuid    primary key default gen_random_uuid(),
  min_master_pw_length  int     not null default 12,
  default_rotation_days int     not null default 90,
  access_token_ttl_sec  int     not null default 300,    -- konfigurabilno za test rotacije
  refresh_token_ttl_sec int     not null default 3600,    -- tehnicki prozor jednog refresh tokena
  session_max_ttl_sec   int     not null default 1800,    -- = "trajanje sesije" (apsolutni cap od logina); admin-definisano
  honeypot_endpoint     boolean not null default false,  -- admin pali ranjivi test-endpoint
  is_active             boolean not null default true,
  updated_by_id         uuid,
  updated_at            timestamptz not null default now()
);
create index idx_policy_active on security_policy(is_active);

create table audit_log (
  id         uuid        primary key default gen_random_uuid(),
  seq        bigserial   unique,                  -- monotono rastući redosled
  actor_id   uuid,
  action     varchar(32) not null,
  resource   varchar(255),
  metadata   jsonb       not null default '{}',
  prev_hash  varchar(64) not null,                -- heš prethodnog zapisa
  hash       varchar(64) not null unique,         -- SHA-256(canonical(payload) || prevHash)
  created_at timestamptz not null default now()
);
create index idx_audit_actor on audit_log(actor_id);
create index idx_audit_seq on audit_log(seq);

create table audit_anchor (
  id           uuid        primary key default gen_random_uuid(),
  from_seq     bigint      not null,
  to_seq       bigint      not null,
  head_hash    varchar(64) not null,              -- vrh lanca u trenutku sidrenja
  channel      varchar(32) not null,              -- 'email' | 's3' | 'chain'
  external_ref varchar(255),                       -- npr. tx hash / message id
  created_at   timestamptz not null default now()
);

create table honeytoken (
  id         uuid        primary key default gen_random_uuid(),
  label      varchar(255) not null,                -- izgleda kao realan resurs
  fake_blob  bytea        not null,
  created_at timestamptz  not null default now()
);

create table security_event (
  id         uuid        primary key default gen_random_uuid(),
  type       varchar(32) not null,                -- 'HONEYPOT_HIT'|'IP_BLOCKED'|'ACCOUNT_FROZEN'|'BRUTEFORCE'
  user_id    uuid,
  ip         varchar(64),
  detail     jsonb       not null default '{}',
  created_at timestamptz not null default now()
);
create index idx_event_type on security_event(type);
create index idx_event_user on security_event(user_id);

create table refresh_token (
  id           uuid        primary key default gen_random_uuid(),
  user_id      uuid        not null references users(id),
  token_hash   varchar(64) not null unique,
  rotated_from uuid,
  revoked      boolean     not null default false,
  expires_at   timestamptz not null,
  created_at   timestamptz not null default now()
);
create index idx_refresh_user on refresh_token(user_id);
```

> **Invarijanta zero-knowledge:** server nikad ne sme primiti niti logovati: master lozinku,
> master key, KEK, USK (plaintext), privatni ključ (plaintext), `secretKey` (plaintext),
> niti plaintext sadržaj tajne. Sve gore je `bytea` u šifrovanom obliku.

---

## 4. Inkrementalni Plan Implementacije (Step-by-Step Blueprint)

> Posle SVAKE faze: pokreni testove, ispuni Acceptance Criteria, čekiraj fazu u `PROGRESS.md`,
> napravi git commit sa porukom `feat(fazaN): <opis>`. Tek onda nastavi.

### Faza 0 — Setup i Konfiguracija
**Cilj:** Pokrenuta infrastruktura i prazni servisi koji se "vide" međusobno.
**Zadaci:**
1. Inicijalizuj monorepo i strukturu iz 2.2 (dva Maven projekta: `backend`, `gateway`; npm projekat: `frontend`).
2. Napravi `docker-compose.yml` sa servisima: `postgres`, `redis`, `backend`, `gateway`, `frontend`.
3. Napravi `.env.example` (DB URL, REDIS URL, JWT_SECRET, SERVER_KMS_KEY, OIDC_* placeholderi, ACCESS_TTL).
4. Backend: Spring Boot skeleton + `GET /health` kontroler (ili Actuator). Gateway: Spring Cloud Gateway + ruta ka backendu + sopstveni `/health`.
5. Frontend: Vite + React skeleton koji gađa gateway `/health`.
**Acceptance Criteria:**
- `docker compose up` diže svih 5 servisa bez grešaka.
- `curl http://localhost:8080/health` (gateway) vraća `200 {"status":"ok"}` i proxy-uje backend health.
- Frontend u browseru prikazuje status "backend: ok".

### Faza 1 — Data Layer i Migracije
**Cilj:** Šema iz sekcije 3 živa u Postgresu.
**Zadaci:**
1. Ubaci `V1__init.sql` (DDL iz 3.2) u `backend/src/main/resources/db/migration`.
2. Konfiguriši Flyway (auto-migrate na startu) i Hibernate `ddl-auto=validate`. Napiši JPA entitete za sve tabele.
3. Seed (`V2__seed.sql` ili `CommandLineRunner`): jedan `ADMIN` nalog (placeholder kripto polja popunjena nasumično za sad), jedan aktivan `security_policy`, par `honeytoken` redova.
4. Implementiraj Spring Data JPA repozitorijume po feature-u.
**Acceptance Criteria:**
- `flyway info` (ili log na startu) pokazuje sve migracije primenjene ("Success").
- Seed prolazi; `SELECT count(*) FROM security_policy WHERE is_active = true` = 1.
- Unit test (`@DataJpaTest`): repozitorijum može da kreira i pročita `User` red.

### Faza 2 — Klijentski Kripto Sloj (temelj zero-knowledge)
**Cilj:** Reuzabilan, testiran kripto modul na frontendu (samo Web Crypto API). (Bez UI-ja još.)
**Zadaci:**
1. `frontend/src/crypto/kdf.ts`: `deriveMasterKey(pw, salt, iterations)` (PBKDF2-HMAC-SHA256, `crypto.subtle`).
2. `crypto/derive.ts`: `deriveKek(masterKey)` i `deriveAuthKey(masterKey)` preko HKDF (`info="vault-kek"`/`"vault-auth"`).
3. `crypto/sym.ts`: `aesGcmEncrypt/Decrypt(key, data)` (vraća/čita nonce+ciphertext).
4. `crypto/asym.ts`: `generateKeyPair()` (RSA-OAEP 2048), `wrapTo(publicKey, data)`, `unwrap(privateKey, box)`.
5. `crypto/vault.ts`: visoke funkcije — `bootstrapKeys(pw)` (generiše USK+keypair, vraća encUsk/encPrivateKey/publicKey/authKey), `unlock(pw, salt, iterations, encUsk, encPrivateKey)`.
**Acceptance Criteria:**
- Vitest: `unlock(bootstrap output)` rekonstruiše isti USK i privatni ključ (round-trip).
- Test: `wrapTo(pubB, x)` → `unwrap(privB, ...)` vraća `x`; privatni ključ A NE može da otvori.
- Test: AES-GCM dekripcija sa pogrešnim ključem baca grešku (autentikacija radi).
- Negativan test: nijedna funkcija ne emituje plaintext ključ kroz network mock.

### Faza 3 — Registracija i Skladištenje Ključeva
**Cilj:** Korisnik se registruje; server čuva samo šifrovane artefakte.
**Zadaci:**
1. Backend `user` modul: `POST /users/register` prima `{username,email,kdfSalt,kdfIterations,authKey,encUsk,publicKey,encPrivateKey}`.
2. Server re-hešuje: čuva `bcrypt(authKey)` u `auth_hash`; validira (Bean Validation) da NIJEDNO polje nije plaintext ključ (veličine/format).
3. Frontend `features/auth/Register`: generiše salt, poziva `bootstrapKeys`, šalje paket.
4. Audit zapis registracije (privremeno bez lanca; lanac dolazi u Fazi 11 — koristi stub `prevHash="GENESIS"`).
**Acceptance Criteria:**
- `POST /users/register` vraća `201`; u DB `auth_hash` ≠ poslati `authKey`.
- `enc_usk`, `enc_private_key`, `public_key` upisani kao `bytea`, ne-prazni.
- Verifikacija: ne postoji nijedna kolona koja sadrži plaintext lozinku/USK/privatni ključ.

### Faza 4 — Autentikacija (lozinka + MFA + sesije)
**Cilj:** Pun login tok sa TOTP-om i rotacijom tokena.
**Zadaci:**
1. `POST /auth/login/step1` — prima `{username, authKey}`; server poredi `bcrypt(authKey)`; vraća `mfaRequired:true` + privremeni `mfaTicket`.
2. TOTP setup: `POST /auth/totp/setup` (vraća otpauth URI/QR, `dev.samstevens.totp`), `POST /auth/totp/verify` (uključuje `totp_enabled`).
3. `POST /auth/login/step2` — prima `{mfaTicket, totpCode}`; verifikuje TOTP; izdaje access JWT (jjwt, TTL iz politike) + refresh token; postavlja `HttpOnly; Secure; SameSite=Strict` kolačiće.
4. `POST /auth/refresh` — rotira refresh token (stari revoked u Redisu/DB), izdaje nov access. Istek novog refresh tokena je `min(now + refresh_token_ttl_sec, session_expires_at)`; ako je `session_expires_at` (apsolutni cap iz politike) prošao → odbij refresh (`401`) i traži ponovni login.
5. Frontend: posle login-a klijent poziva `unlock(pw,...)` na osnovu vraćenih `encUsk/encPrivateKey`; ključevi žive samo u Context memoriji.
**Acceptance Criteria:**
- Login bez validnog TOTP-a → `401`.
- Pun tok (step1→TOTP→step2) postavlja 2 kolačića sa ispravnim flegovima (proveriti `Set-Cookie`).
- Posle `access_token_ttl_sec`, zaštićeni endpoint vraća `401`; `/auth/refresh` izda nov access; stari refresh više ne radi (rotacija).
- Posle `session_max_ttl_sec` od logina, `/auth/refresh` vraća `401` čak i sa važećim refresh tokenom (apsolutni cap sesije); jedini izlaz je ponovni login.
- E2E: posle login-a frontend uspešno otključa i drži USK u memoriji (ne u storage-u).

### Faza 5 — OIDC Prijava
**Cilj:** Prijava preko eksternog naloga, uz očuvan zero-knowledge.
**Zadaci:**
1. `GET /auth/oidc/start` → redirect na provajdera (Spring Security OAuth2 client).
2. OIDC callback → validacija, mapiranje `oidc_subject` na User, izdavanje sesije.
3. Frontend: posle OIDC sesije i dalje traži master lozinku i poziva `unlock` (OIDC ne daje ključ).
**Acceptance Criteria:**
- Uspešan callback kreira sesiju i kolačiće kao u Fazi 4.
- Eksplicitan test/dokaz: nakon OIDC logina vault je i dalje "locked" dok korisnik ne unese master lozinku.

### Faza 6 — Vault CRUD
**Cilj:** Kreiranje/čitanje/izmena/brisanje tajni, sve šifrovano na klijentu.
**Zadaci:**
1. Frontend: za novu tajnu generiši `secretKey`, `encryptedBlob = AES-GCM(secretKey, plaintext)`, `wrappedForOwner = wrapTo(myPublicKey, secretKey)`.
2. `POST /vault/secrets` čuva `secrets` + `secret_access` (vlasnik). Regularni upiti filtriraju `is_honeytoken=false`.
3. `GET /vault/secrets` (lista metapodataka), `GET /vault/secrets/:id` (vraća blob + moj `wrappedSecretKey`).
4. `PUT`/`DELETE` uz proveru vlasništva/pristupa.
5. Frontend dekripcija: `secretKey = unwrap(myPrivateKey, wrapped)` → `plaintext = AES-GCM(secretKey, blob)`.
**Acceptance Criteria:**
- Create→Read round-trip vraća identičan plaintext u browseru.
- DB inspekcija: `encrypted_blob` je nečitljiv; nijedan endpoint ne vraća plaintext.
- `GET /vault/secrets` NIKAD ne vraća honeytoken redove.
- Korisnik bez pristupa dobija `403` na `GET /vault/secrets/:id`.

### Faza 7 — Sigurno Deljenje (envelope)
**Cilj:** Team Lead deli tajnu sa Developerom bez da server dešifruje.
**Zadaci:**
1. `GET /users/:id/public-key`.
2. Frontend (A): `secretKey = unwrap(myPrivateKey, ...)` → `wrappedForB = wrapTo(pubB, secretKey)`.
3. `POST /vault/secrets/:id/share` `{recipientId, wrappedSecretKey}` → kreira `secret_access` red (uloga `TEAM_LEAD` obavezna, `@PreAuthorize`).
4. Frontend (B): vidi deljenu tajnu, otvara svojim privatnim ključem.
**Acceptance Criteria:**
- Posle deljenja, B dekriptuje istu tajnu; `encrypted_blob` je NEPROMENJEN (isti hash kao pre deljenja).
- `Developer` koji pokuša share → `403`.
- DB: `wrapped_secret_key` za A i B se razlikuju; nijedan nije plaintext.

### Faza 8 — Admin i Sigurnosne Politike
**Cilj:** Admin upravlja nalozima i politikama; klijentski scenariji rotacije/promene lozinke.
**Zadaci:**
1. `user` admin endpointi: `PATCH /admin/users/:id/status` (ACTIVE/DEACTIVATED) — Admin SAMO aktivira/deaktivira.
2. `PATCH /admin/policy` (min dužina, rotationDays, TTL-ovi). "Trajanje sesije" se izlaže adminu kao `session_max_ttl_sec` (apsolutni cap od logina); `access_token_ttl_sec` je zaseban tehnički prozor rotacije, `refresh_token_ttl_sec` trajanje pojedinačnog refresh tokena.
3. Frontend scenario "povećana min dužina": klijent dohvati novu dužinu → proveri da li je trenutna lozinka kraća → ako jeste, polje za novu lozinku → re-deriv KEK → re-šifruj `encUsk` i `encPrivateKey` → `POST /auth/rotate-master`.
4. Frontend rotacija tajni: rok rotacije ne okida ništa automatski (server je zero-knowledge, ne vidi plaintext). Kad vlasnik **otvori** tajnu, klijent poredi `rotated_at + rotation_days` sa sada → ako je isteklo prikaže **UI upozorenje** ("Tajna je istekla — preporučena rotacija") sa akcijom "Rotiraj sada". Na potvrdu: generiše nov `secretKey`, re-šifruje blob, ažurira sve `secret_access` (re-wrap ka svim postojećim primaocima) → `PUT`.
**Acceptance Criteria:**
- Deaktiviran korisnik ne može da se uloguje (`403` u step1).
- Posle `rotate-master`, login sa NOVOM lozinkom otključava sve postojeće tajne (blobovi netaknuti).
- Otvaranje tajne čiji je `rotated_at + rotation_days` u prošlosti prikazuje UI upozorenje o isteku; tajna sa `rotation_days = null` ili nevažećim rokom ga NE prikazuje.
- Test rotacije tajne: stara `wrapped_secret_key` više ne otvara novi blob; nova otvara.

### Faza 9 — API Gateway i Rate Limiting
**Cilj:** Sve ide kroz gateway; brute-force i sumnjive sekvence se blokiraju.
**Zadaci:**
1. Premesti sav frontend saobraćaj kroz gateway (`:8080`); backend nije direktno dostupan spolja (Docker network).
2. Spring Cloud Gateway `RequestRateLimiter` (`RedisRateLimiter`): striktan limit na `/auth/login/**`, blaži globalni; `KeyResolver` po IP adresi.
3. `IpGuardFilter` (`GlobalFilter` + Redis): brojač neuspešnih login-a / isteklih sesijskih tokena / dekripcionih grešaka **i detekcija sumnjivih sekvenci unosa** (SQLi/payload uzorci) po IP; prag → privremeni blok + `security_event("IP_BLOCKED")`.
**Acceptance Criteria:**
- N+1 uzastopnih neuspešnih login-a sa istog IP → `429` i red u `security_event`.
- Direktan pristup backend portu spolja je nemoguć (connection refused / nije izložen).
- Legitiman saobraćaj nije pogođen ispod praga.

### Faza 10 — Honeypot i Honeytokens
**Cilj:** Detekcija upada preko lažnih tajni.
**Zadaci:**
1. Honeytoken redovi (`is_honeytoken=true` / `honeytoken` tabela) nevidljivi regularnom API-ju.
2. Logika okidača: bilo koji pristup honeytokenu → `FROZEN` status aktivnog korisnika + `security_event("HONEYPOT_HIT")` + alarm adminu.
3. Admin-togglable ranjivi test-endpoint (`policy.honeypot_endpoint=true`) koji namerno gradi SQL upit konkatenacijom stringova (raw `JdbcTemplate`/native query) nad honeytoken podacima — izolovan, samo za demonstraciju SQL Injection-a.
**Acceptance Criteria:**
- Sa `honeypot_endpoint=true`, SQLi payload koji dohvati honeytoken → nalog postaje `FROZEN`, `security_event` kreiran, admin alarm poslat.
- Sa `honeypot_endpoint=false`, taj endpoint vraća `404`.
- Regularni `GET /vault/secrets` i dalje ne otkriva honeytokene.

### Faza 11 — Imutable Audit Log (hash lanac + anchoring)
**Cilj:** Nepromenljiv trag svih akcija.
**Zadaci:**
1. `AuditService.append(action, actorId, resource, metadata)`: učita poslednji `hash`, izračuna `hash = SHA-256(canonicalJSON(payload) || prevHash)` (java.security `MessageDigest`), upiše `seq`.
2. Zameni sve stub audit pozive iz ranijih faza pravim lancem.
3. `verifyChain()` — prolazi ceo lanac i potvrđuje konzistentnost.
4. Anchoring job (`@Scheduled`): periodično `headHash` šalje na nezavisni kanal (minimalno: email adminu; opciono S3 read-only/blockchain) → `audit_anchor`.
**Acceptance Criteria:**
- `verifyChain()` = `true` na netaknutom logu.
- Test: ručna izmena jednog starog `metadata` u DB → `verifyChain()` = `false` od tog `seq` nadalje.
- Anchoring job kreira `audit_anchor` red i šalje `headHash` na konfigurisani kanal.
- Brisanje/izmena se ne mogu izvesti kroz API (append-only; nema UPDATE/DELETE ruta).

### Faza 12 — Integracija, Hardening i Dockerizacija
**Cilj:** Sve povezano, kontejnerizovano, produkciono-spremno za odbranu.
**Zadaci:**
1. Spring Security sigurnosni headeri (`headers()`), CORS striktno na gateway origin.
2. Finalni `docker-compose` (multi-stage Dockerfile-ovi, healthcheck-ovi, mreže), validacija env varijabli na startu.
3. README sa uputstvom za pokretanje + demo skripta (registracija→share→honeypot→audit verify).
**Acceptance Criteria:**
- `docker compose up --build` diže ceo sistem; demo skripta prolazi end-to-end.
- Svi unit/integration testovi prolaze: `mvn test` (backend, gateway) i `npm test` (frontend).
- Sigurnosni headeri prisutni; backend nedostupan spolja.

---

## 5. Konvencije Kodiranja

### 5.1 Imenovanje
- `camelCase` — Java varijable/metode/polja; TS varijable, funkcije, properties.
- `PascalCase` — Java klase/interfejsi/enumi, TS tipovi/interfejsi, React komponente, Spring komponente (`@Service`, `@RestController`).
- `snake_case` — Postgres tabele i kolone (JPA `@Table`/`@Column` mapiranje na camelCase polja entiteta).
- `kebab-case` — frontend imena fajlova i foldera (`auth-context.ts`, `secret-list/`); Java fajl = ime klase (`UserService.java`).
- `SCREAMING_SNAKE_CASE` — env varijable i globalne konstante (`ACCESS_TOKEN_TTL_SEC`).
- Sufiksi: DTO → `Request`/`Response`/`Dto`; repozitorijum → `Repository`; servis → `Service`; kontroler → `Controller`.

### 5.2 Error Handling
- Aplikacioni sloj baca tipizovane greške (`UnauthorizedException`, `ForbiddenException`, `NotFoundException`, `ValidationException`, `CryptoException`).
- Spring `@RestControllerAdvice` (`GlobalExceptionHandler`) mapira greške u konzistentan oblik:
```json
  { "error": { "code": "FORBIDDEN", "message": "..." } }
```
- NIKAD ne vraćati interne detalje (stack trace, SQL, imena kolona) klijentu.
- NIKAD ne logovati: lozinke, master key, USK, privatne/secret ključeve, plaintext tajne, TOTP tajne.
- Kripto operacije (na klijentu): neuspeh dekripcije/auth taga = jasna greška, bez "tihog" fallback-a.
- Gateway: rate-limit/blok vraća `429`; istekla sesija `401`; nedovoljna prava `403`.
- Validacija ulaza: Bean Validation (`@Valid`, Hibernate Validator) na svim DTO; Jackson odbija nepoznata polja (`FAIL_ON_UNKNOWN_PROPERTIES=true`).

### 5.3 Posebna pravila(obavezno)
1. **Bez placeholder-a.** Nikada `// TODO: implement later`, `throw new UnsupportedOperationException()`, ni prazne metode. Svaka faza isporučuje kompletan, funkcionalan, izvršiv kod.
2. **Bez sopstvene kriptografije.** Frontend koristi isključivo **Web Crypto API** (`crypto.subtle`). Backend koristi standardne biblioteke: `java.security` (`MessageDigest`, `SecureRandom`), Spring Security Crypto, `jjwt`, `dev.samstevens.totp`.
3. **Zero-knowledge je neprekršiv.** Pre svakog backend endpointa proveri: da li bi server mogao da vidi plaintext? Ako da — dizajn je pogrešan, stani i preispitaj.
4. **Klijentska enkripcija.** Sva enkripcija/dekripcija sadržaja tajni i ključeva ide u `frontend/src/crypto`. Backend samo skladišti/prosleđuje `byte[]`.
5. **Testovi su deo isporuke**, ne naknadna misao. Svaka faza dodaje testove navedene u njenim kriterijumima.
6. **Idempotentne migracije i seed.** Ponovno pokretanje ne sme da puca (Flyway verzionisane migracije, seed sa `ON CONFLICT`/provera).
7. **Tajne i konfiguracija** uvek iz env varijabli / `application.yml` placeholdera; nikad hardkodovane vrednosti u kodu.
8. **Append-only audit.** Nema UPDATE/DELETE ruta nad `audit_log`.
9. **Commit po fazi** sa porukom `feat(fazaN): <kratak opis>`.

### 5.4 PROGRESS.md (AI održava)
```
- [ ] Faza 0  — Setup i Konfiguracija
- [ ] Faza 1  — Data Layer i Migracije
- [ ] Faza 2  — Klijentski Kripto Sloj
- [ ] Faza 3  — Registracija i Skladištenje Ključeva
- [ ] Faza 4  — Autentikacija (lozinka + MFA + sesije)
- [ ] Faza 5  — OIDC Prijava
- [ ] Faza 6  — Vault CRUD
- [ ] Faza 7  — Sigurno Deljenje
- [ ] Faza 8  — Admin i Sigurnosne Politike
- [ ] Faza 9  — API Gateway i Rate Limiting
- [ ] Faza 10 — Honeypot i Honeytokens
- [ ] Faza 11 — Imutable Audit Log
- [ ] Faza 12 — Integracija i Dockerizacija
```
