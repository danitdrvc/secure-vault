# Secure Vault

Zero-knowledge sistem za sigurno upravljanje tajnama (lozinke, API ključevi, sertifikati).
Sva enkripcija i dekripcija dešavaju se **isključivo u čitaču (klijentu)**; server u bazu upisuje
samo šifrovane blobove, javne ključeve i hešove — nikada ne vidi master lozinku niti
dekriptovani sadržaj tajni.

> Detaljan plan i obrazloženja dizajna: [`DEVELOPMENT_PLAN.md`](DEVELOPMENT_PLAN.md).
> Status po fazama: [`PROGRESS.md`](PROGRESS.md).
> **Korak-po-korak uputstvo za ručno testiranje (browser / konzola / pgAdmin):**
> [`TESTIRANJE.md`](TESTIRANJE.md).

---

## Arhitektura

```
  Browser (React SPA, :5173)
        │  HTTPS/HTTP  (samo /api/**, sa kolačićima)
        ▼
  API Gateway (Spring Cloud Gateway, :8080)   ← jedina ulazna tačka
        │  RedisRateLimiter + IpGuardFilter (CORS, rate-limit, IP blok)
        ▼
  Backend API (Spring Boot, :8081)            ← "slep" na sadržaj
        │
        ├── PostgreSQL 16  (:5432)   — šifrovani blobovi, hash-lanac audita
        └── Redis 7        (:6379)   — rate-limit i IP-guard brojači
```

| Servis | Tehnologija | Port | Uloga |
|---|---|---|---|
| `frontend` | React 18 + TypeScript + Vite | `5173` | SPA; **jedina zona kripto-operacija** (Web Crypto API) |
| `gateway` | Java 21 + Spring Cloud Gateway | `8080` | jedina ulazna tačka; CORS, rate-limit, IP guard |
| `backend` | Java 21 + Spring Boot 3.3 | `8081` | REST API; skladišti samo šifrat (`byte[]`) |
| `postgres` | PostgreSQL 16 | `5432` | šema vlasništvo Flyway-a (`V1`/`V2`) |
| `redis` | Redis 7 | `6379` | backing store za gateway brojače |

Uloge: **Admin** (aktivira/deaktivira naloge, politike — NE upravlja tajnama), **Team Lead**
(deli tajne), **Developer** (kreira/koristi tajne).

> **Napomena:** Docker se **ne koristi** (permanentna odluka — vidi `DEVELOPMENT_PLAN.md`).
> Servisi se pokreću lokalno. `docker-compose.yml` postoji i ispravan je, ali nije obavezan.

---

## Preduslovi

- **JDK 21** (LTS) — npr. Eclipse Temurin 21.
- **Maven 3.9+** (ili koristi sistemski `mvn`).
- **Node.js 20+** i **npm**.
- **PostgreSQL 16** (lokalna instalacija ili servis).
- **Redis 7** (potreban za gateway rate-limit; backend radi i bez njega).

Provera:

```powershell
java -version      # 21.x
mvn -version       # 3.9.x, Java 21
node --version     # 20+
psql --version     # 16.x
```

---

## Inicijalno podešavanje

### 1. Baza podataka (jednokratno)

Kreiraj rolu, bazu i `pgcrypto` ekstenziju (vrednosti se poklapaju sa default-ima u
`application.yml`; promeni ih preko env varijabli za produkciju):

```sql
-- psql -U postgres
CREATE ROLE vault WITH LOGIN PASSWORD 'vault';
CREATE DATABASE securevault OWNER vault;
\c securevault
CREATE EXTENSION IF NOT EXISTS pgcrypto;
GRANT ALL ON SCHEMA public TO vault;
```

Flyway na startu backenda primenjuje migracije (`V1__init.sql`, `V2__seed.sql`) i seed
(1 admin placeholder, 1 aktivna politika, 3 honeytokena).

### 2. Env varijable (opciono za dev, OBAVEZNO za produkciju)

```powershell
Copy-Item .env.example .env   # pa popuni stvarnim vrednostima
```

U dev-u svi servisi imaju razumne lokalne default-e i rade i bez `.env`. **Tajne sa dev
default-ima su NESIGURNE** — vidi „Hardening" niže.

---

## Pokretanje (3 terminala)

```powershell
# Terminal 1 — Backend (:8081)
mvn -f backend/pom.xml spring-boot:run

# Terminal 2 — Gateway (:8080)   [zahteva Redis]
mvn -f gateway/pom.xml spring-boot:run

# Terminal 3 — Frontend (:5173)
cd frontend
npm install      # samo prvi put
npm run dev
```

Otvori **http://localhost:5173** — početna prikazuje „backend: ok" ako je lanac
frontend → gateway → backend ispravan.

Brza provera lanca iz konzole:

```powershell
curl http://localhost:8080/health        # gateway:  {"status":"ok"}
curl http://localhost:8080/api/health    # proxy → backend: {"status":"ok"}
```

---

## Testovi

```powershell
mvn -f backend/pom.xml test     # JUnit + MockMvc nad embedded PostgreSQL-om (bez Dockera)
mvn -f gateway/pom.xml test     # JUnit + WebTestClient (hermetično, bez živog Redis-a)
cd frontend; npm test           # Vitest + Testing Library
```

Svi testovi su hermetični (embedded PG / in-memory fake-ovi) — ne zavise od živih servisa.

---

## Demo skripta (server-side sigurnosna provera)

`demo.ps1` proverava sigurnosnu posturu žive instalacije bez potrebe za klijentskom
kriptografijom: health lanac, sigurnosna zaglavlja, striktan CORS, zaštitu privatnih
endpointa i rate-limiting.

```powershell
# Pokreni backend + gateway (+ Redis) pa:
./demo.ps1
# ili sa drugačijim URL-om gateway-a:
./demo.ps1 -Gateway http://localhost:8080
```

> **End-to-end funkcionalni demo** (registracija → TOTP → vault → deljenje → honeypot →
> audit verify) zahteva browser jer je sva kriptografija klijentska (zero-knowledge).
> Taj tok je dat korak-po-korak u [`TESTIRANJE.md`](TESTIRANJE.md).

---

## Sigurnosni mehanizmi (pregled)

| Mehanizam | Gde | Detalji |
|---|---|---|
| Zero-knowledge kripto | frontend `src/crypto` | PBKDF2 → HKDF → AES-256-GCM + RSA-OAEP (Web Crypto API) |
| Lozinka + MFA | backend `auth` | `bcrypt(authKey)` + TOTP (RFC 6238) |
| Sesije | backend `auth` | access/refresh JWT u `HttpOnly; Secure; SameSite=Strict` kolačićima; rotacija + apsolutni cap |
| OIDC prijava | backend `auth/oidc` | daje samo sesiju — master lozinka i dalje obavezna za unlock |
| Sigurno deljenje | backend `vault` | envelope re-wrap (`secretKey` uvijen ka primaocu; blob netaknut) |
| **Sigurnosna zaglavlja** | backend `SecurityConfig` | CSP `default-src 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, HSTS |
| **Striktan CORS** | gateway `application.yml` | samo frontend origin, eksplicitne metode/zaglavlja, `allowCredentials` |
| Rate limiting | gateway | `RedisRateLimiter` (strog na login, blaži globalno), per-IP |
| IP guard | gateway `IpGuardFilter` | strike → privremeni blok (`429`) + `IP_BLOCKED` događaj; SQLi/payload detekcija |
| Honeypot / honeytokens | backend `honeypot` | pristup honeytokenu → nalog `FROZEN` + `HONEYPOT_HIT` + admin alarm |
| Imutabilni audit | backend `audit` | SHA-256 hash-lanac + `verifyChain()` + periodični anchoring (append-only) |
| **Validacija konfiguracije** | backend/gateway `StartupConfigValidator` | fail-fast na startu; nesigurne dev tajne su greška u `prod` profilu |

---

## Hardening / produkcija

U dev-u tajne imaju nesigurne placeholder vrednosti i `StartupConfigValidator` ih prijavljuje
kao **upozorenja** (`WARN [config] ...`). U produkciji aktiviraj `prod` profil — tada iste
nesigurne vrednosti **obaraju start** (fail-fast):

```powershell
$env:SPRING_PROFILES_ACTIVE = "prod"
```

Produkcioni checklist (postavi pre pokretanja sa `prod` profilom):

- [ ] `JWT_SECRET` — ≥ 32 bajta, slučajan (`openssl rand -base64 48`).
- [ ] `SERVER_KMS_KEY` — slučajan, dugačak (šifruje TOTP tajne u bazi).
- [ ] `INTERNAL_TOKEN` — slučajan; isti na backendu i gateway-u (server-to-server).
- [ ] `POSTGRES_PASSWORD` — jaka lozinka (ne `vault`).
- [ ] `APP_COOKIE_SECURE=true` — sesijski kolačići samo preko HTTPS-a.
- [ ] `FRONTEND_ORIGIN` — tačan origin SPA (CORS).
- [ ] Backend (`:8081`) nije izložen spolja — dostupan samo gateway-u (firewall / mreža).

Svaka stavka koja ostane na dev default-u u `prod` profilu je greška na startu sa jasnom porukom.
