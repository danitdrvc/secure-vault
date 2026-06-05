# PROGRESS — Secure Vault

Status implementacije po fazama (vidi `DEVELOPMENT_PLAN.md`).

- [x] Faza 0  — Setup i Konfiguracija
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
