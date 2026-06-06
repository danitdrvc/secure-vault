# PROGRESS — Secure Vault

Status implementacije po fazama (vidi `DEVELOPMENT_PLAN.md`).

- [x] Faza 0  — Setup i Konfiguracija
- [x] Faza 1  — Data Layer i Migracije
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
