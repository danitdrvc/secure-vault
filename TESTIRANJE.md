# Secure Vault — Uputstvo za ručno testiranje (korak po korak)

Ovo uputstvo te vodi kroz **sve bitne funkcionalnosti** sistema, prvenstveno **u browseru**, uz
**DevTools konzolu** (za autentikovane API pozive) i **pgAdmin / psql** (za dokaz da je server
„slep" — zero-knowledge — i za pripremu test-scenarija).

> Legenda:
> - 🌐 **Browser** — radnja u korisničkom interfejsu (http://localhost:5173).
> - 🧪 **Konzola** — DevTools → Console (F12). Pozivi koriste sesijske kolačiće (`credentials:'include'`).
> - 🗄️ **pgAdmin** — SQL upit nad bazom `securevault` (ili `psql`).
> - ✅ **Očekivano** — šta treba da vidiš da bi test prošao.

---

## 0. Priprema okruženja

### 0.1 Pokreni infrastrukturu i servise

1. **PostgreSQL 16** i **Redis 7** su pokrenuti. (Baza/rola/`pgcrypto` — vidi `README.md` § „Inicijalno
   podešavanje". Redis je potreban za rate-limiting / IP guard.)
2. U tri terminala:
   ```powershell
   mvn -f backend/pom.xml spring-boot:run     # :8081
   mvn -f gateway/pom.xml spring-boot:run     # :8080  (treba Redis)
   cd frontend; npm run dev                    # :5173
   ```
3. 🌐 Otvori **http://localhost:5173**. Na početnoj strani treba da piše **„backend: ok"**.
4. 🧪 Brza provera lanca (može i u običnom terminalu):
   ```powershell
   curl http://localhost:8080/health        # {"status":"ok"}  (gateway)
   curl http://localhost:8080/api/health    # {"status":"ok"}  (proxy → backend)
   ```

✅ Sve tri komponente odgovaraju; početna prikazuje „backend: ok".

### 0.2 Otvori pgAdmin

Poveži se na bazu `securevault` (rola `vault`). Koristićeš ga za dokaze zero-knowledge svojstava i za
pripremu scenarija (uloge, honeytokeni, rotacija). Korisni upiti su u **Dodatku A** na kraju.

---

## 1. Registracija (zero-knowledge skladištenje)

1. 🌐 Idi na **Registracija** (`/register`).
2. Unesi: korisničko ime `alice`, email `alice@example.com`, master lozinku (min. 12 znakova, npr.
   `AliceMaster123!`), i potvrdu.
3. Klikni **Registruj se**.

✅ Poruka: „Nalog `alice` je kreiran (uloga: DEVELOPER)."

### 1.1 Dokaz: server NE vidi lozinku ni ključeve

🗄️ U pgAdmin pokreni:
```sql
SELECT username, role, status,
       left(auth_hash, 7)        AS auth_hash_prefix,   -- bcrypt počinje sa $2a$/$2b$
       length(enc_usk)           AS enc_usk_bytes,       -- ~60 B, šifrat
       length(public_key)        AS public_key_bytes,
       length(enc_private_key)   AS enc_priv_bytes,      -- > 1200 B, šifrat
       kdf_iterations
FROM users WHERE username = 'alice';
```

✅ `auth_hash_prefix` je `$2a$...` (bcrypt **heš**, ne tvoja lozinka i ne `authKey`); `enc_usk`,
`public_key`, `enc_private_key` su ne-prazni **bytea** šifrati. **Nigde nema kolone sa master lozinkom,
USK-om ni privatnim ključem u plaintextu.** `kdf_iterations` = 600000.

---

## 2. Prva prijava + MFA (TOTP) + sesije

1. 🌐 Idi na **Prijava** (`/login`). Unesi `alice` + master lozinku → **Dalje**.
2. Pošto je ovo prvi login, prikazuje se **QR kod** za TOTP (drugi faktor):
   - **Najlakše:** skeniraj QR u authenticator aplikaciji (Google Authenticator, Authy, Microsoft
     Authenticator…) na telefonu.
   - **Bez telefona:** otvori DevTools → **Network**, nađi odgovor poziva `totp/setup`, kopiraj polje
     `otpauthUri` (sadrži `secret=...` u Base32) i ubaci ga u desktop/online TOTP generator.
3. Unesi 6-cifreni kod → **Uključi i prijavi se**.

✅ Poruka: „Prijavljeni ste kao `alice`. Vault je otključan u memoriji."

### 2.1 Dokaz: ispravni sesijski kolačići

🌐 DevTools → **Application** → **Cookies** → `http://localhost:8080`:

✅ Postoje **`sv_access`** i **`sv_refresh`**, oba sa **`HttpOnly`** i **`SameSite=Strict`**.
(`Secure` je uključen samo kad je `APP_COOKIE_SECURE=true` / HTTPS — u lokalnom http dev-u je isključen.)

### 2.2 Dokaz: ključevi žive SAMO u memoriji (zero-knowledge)

🌐 DevTools → **Application** → **Local Storage** i **Session Storage** za `localhost:5173`.

✅ **Prazno** — nema USK-a, privatnog ključa ni master lozinke. Osveži stranicu (F5): vault postaje
„zaključan" i traži ponovni unlock (jer ključevi nisu nigde perzistirani).

### 2.3 (Opciono) Dokaz: pogrešan TOTP → 401

Odjavi se (**Nova prijava**), ponovi login i namerno unesi pogrešan TOTP kod.
✅ Prijava ne uspeva (`401`), bez postavljanja kolačića.

---

## 3. Vault — kreiranje, čitanje, izmena, brisanje (CRUD)

1. 🌐 Idi na **Vault** (`/vault`) kao prijavljena `alice`.
2. **Nova tajna**: Naziv `Gmail lozinka`, Sadržaj `super-tajna-vrednost-123`, Rok rotacije ostavi prazno
   → **Sačuvaj tajnu**.
3. U listi „Moje tajne" klikni **Prikaži** → sadržaj se dešifruje **u browseru** i prikazuje.
4. Izmeni sadržaj u polju → **Sačuvaj izmene** → **Prikaži** ponovo da potvrdiš izmenu.

✅ Round-trip (kreiranje → čitanje) vraća identičan plaintext.

### 3.1 Dokaz: server čuva samo nečitljiv šifrat

🗄️
```sql
SELECT s.name, length(s.encrypted_blob) AS blob_bytes,
       encode(substring(s.encrypted_blob from 1 for 16), 'hex') AS prvih_16_bajtova
FROM secrets s JOIN users u ON u.id = s.owner_id
WHERE u.username = 'alice' AND s.is_honeytoken = false;
```

✅ `encrypted_blob` je binarni šifrat (heks bez ikakvog smisla) — `prvih_16_bajtova` je nasumičan
nonce, nigde nema plaintext-a tajne.

### 3.2 Dokaz: honeytokeni se NIKAD ne vraćaju regularnom API-ju

🗄️ Seed je ubacio honeytokene u tabelu `honeytoken`:
```sql
SELECT label FROM honeytoken;   -- AWS_PROD_ACCESS_KEY, db-root-credentials, stripe_live_secret_key
```
🌐 U listi „Moje tajne" tih naziva **nema**. (Honeypot okidač testiramo u § 11.)

---

## 4. Uloge: promovisanje korisnika preko baze (priprema za § 5–6)

Registracija uvek pravi `DEVELOPER`-a, a seed-ovani `admin` se ne može prijaviti (placeholder kripto
polja). Zato uloge dodeljuješ ručno u bazi, pa se **ponovo prijaviš** (uloga je upisana u access token).

🗄️ Napravi i drugog korisnika u browseru (registruj `bob` / `bob@example.com`), pa dodeli uloge:
```sql
UPDATE users SET role = 'TEAM_LEAD' WHERE username = 'alice';
UPDATE users SET role = 'ADMIN'     WHERE username = 'bob';   -- bob će biti i admin (za § 6, 11, 12)
SELECT id, username, role FROM users ORDER BY created_at;
```

> ⚠️ Posle promene uloge **odjavi se i ponovo prijavi** (Nova prijava) da bi novi access token nosio
> novu ulogu. Zapamti **`id` (UUID)** korisnika — trebaće za deljenje i admin radnje.

---

## 5. Sigurno deljenje tajne (Team Lead → Developer)

Preduslov: `alice` je `TEAM_LEAD` (§ 4) i ponovo se prijavila; postoji `bob` (`DEVELOPER` za ovaj test —
ako si ga gore napravio `ADMIN`, za čisti test deljenja napravi trećeg korisnika `carol` kao
`DEVELOPER`, ili privremeno vrati `bob` na `DEVELOPER`).

1. 🗄️ Nađi UUID primaoca: `SELECT id FROM users WHERE username = 'bob';`
2. 🌐 Kao `alice` na **Vault**: pored tajne klikni **Podeli** (dugme je vidljivo samo `TEAM_LEAD`-u),
   nalepi `bob`-ov UUID → **Podeli tajnu**.
   ✅ Poruka: „Tajna je podeljena (secretKey uvijen ka primaocu; blob netaknut)."
3. 🌐 Odjavi `alice`, prijavi se kao `bob`, idi na **Vault** → deljena tajna je u listi → **Prikaži**.
   ✅ `bob` dešifruje **isti** plaintext.

### 5.1 Dokaz: blob nepromenjen, ključ po-korisniku različit

🗄️
```sql
SELECT u.username, length(sa.wrapped_secret_key) AS wrapped_bytes,
       encode(substring(sa.wrapped_secret_key from 1 for 8), 'hex') AS prvih_8
FROM secret_access sa
JOIN users u   ON u.id = sa.user_id
JOIN secrets s ON s.id = sa.secret_id
WHERE s.name = 'Gmail lozinka';
```

✅ Dva reda (alice i bob), oba `wrapped_secret_key` = 256 B ali **različitih bajtova** (svaki uvijen ka
svom javnom ključu). `encrypted_blob` tajne se NIJE menjao deljenjem.

### 5.2 Dokaz: Developer ne sme da deli (403)

🌐 Prijavi se kao običan `DEVELOPER`; na njegovoj tajni **nema** dugmeta „Podeli". Pokušaj i direktno:
🧪 (u konzoli, prijavljen kao developer)
```js
await fetch('http://localhost:8080/api/vault/secrets/<SECRET_UUID>/share', {
  method:'POST', credentials:'include',
  headers:{'Content-Type':'application/json'},
  body: JSON.stringify({ recipientId:'<NEKI_UUID>', wrappedSecretKey:'AAAA...' })
}).then(r=>r.status)
```
✅ Vraća **403** (server forsira `@PreAuthorize('TEAM_LEAD')` nezavisno od UI-ja).

---

## 6. Admin — status naloga i sigurnosne politike

Preduslov: prijavljen kao **ADMIN** (`bob` iz § 4).

1. 🌐 Idi na **Admin** (`/admin`). Vidiš „Status naloga" i „Sigurnosna politika".

### 6.1 Deaktivacija naloga

1. 🗄️ Uzmi UUID neke žrtve: `SELECT id FROM users WHERE username = 'alice';`
2. 🌐 Nalepi UUID u „ID korisnika" → **Deaktiviraj**. ✅ „Nalog `alice` je sada DEACTIVATED."
3. 🌐 Odjavi se i pokušaj prijavu kao `alice`. ✅ Prijava odbijena već u prvom koraku (**403**).
4. 🌐 Vrati nazad: kao admin → **Aktiviraj** isti UUID. ✅ `alice` se ponovo može prijaviti.

### 6.2 Izmena politike

🌐 U „Sigurnosna politika" promeni npr. **Min. dužina master lozinke** na `16`, **Access token TTL** na
`60`, sačuvaj. ✅ „Sigurnosna politika je sačuvana."

🗄️ Provera:
```sql
SELECT min_master_pw_length, access_token_ttl_sec, refresh_token_ttl_sec,
       session_max_ttl_sec, honeypot_endpoint, is_active
FROM security_policy WHERE is_active = true;
```

### 6.3 Dokaz: admin NE upravlja tajnama

🌐 Na Admin strani nema nikakvog pristupa tuđim tajnama — admin menja samo status i politiku
(zero-knowledge važi i za admina).

---

## 7. Promena master lozinke (re-šifrovanje USK-a, tajne netaknute)

Preduslov: prijavljen kao `alice` koja ima bar jednu tajnu.

1. 🌐 Idi na **Lozinka** (`/account`). Ako je admin podigao min. dužinu (§ 6.2), forma upozorava ako je
   trenutna lozinka kraća.
2. Unesi staru i novu master lozinku (npr. `AliceMaster123!` → `AliceNoviMaster456!`) → sačuvaj.
   ✅ Uspeh; sesija ostaje (USK je nepromenjen).
3. 🌐 Odjavi se, prijavi se **novom** lozinkom, otvori Vault → **Prikaži** postojeću tajnu.
   ✅ Tajna se i dalje otključava (blob nije diran; promenjen je samo sloj koji štiti USK).

🗄️ (Opciono) pre/posle uporedi `enc_usk` i `auth_hash` — promenili su se; `encrypted_blob` tajne nije.

---

## 8. Rotacija tajne (nov ključ + re-wrap svim primaocima)

1. 🌐 Kao `alice` napravi tajnu `API token` sa **Rok rotacije = 90**.
2. 🗄️ Gurni datum rotacije u prošlost da „istekne":
   ```sql
   UPDATE secrets SET rotated_at = now() - interval '400 days' WHERE name = 'API token';
   ```
3. 🌐 Vault → **Prikaži** tajnu `API token`. ✅ Iskače žuto upozorenje **„Tajna je istekla — preporučena
   rotacija"** sa dugmetom **Rotiraj sada**.
4. 🗄️ Zapamti trenutni ključ pre rotacije:
   ```sql
   SELECT encode(substring(encrypted_blob from 1 for 8),'hex') AS blob8,
          encode(substring(sa.wrapped_secret_key from 1 for 8),'hex') AS wrap8
   FROM secrets s JOIN secret_access sa ON sa.secret_id = s.id
   WHERE s.name = 'API token';
   ```
5. 🌐 Klikni **Rotiraj sada**. ✅ „Tajna je rotirana (nov ključ; stari više ne otvara novi sadržaj)."
6. 🗄️ Ponovi upit iz koraka 4. ✅ I `blob8` i `wrap8` su **drugačiji** — nov `secretKey`, re-šifrovan blob
   i re-wrap ka svim primaocima.

> Tajna sa `rotation_days = NULL` (prazan rok) **ne** prikazuje upozorenje.

---

## 9. OIDC prijava (opciono — eksterni provajder)

Podrazumevano je **isključeno** (`OIDC_ENABLED=false`) i `/auth/oidc/**` vraća **404**.

🧪 Dokaz da je isključeno:
```js
await fetch('http://localhost:8080/api/auth/oidc/start', {redirect:'manual'}).then(r=>r.status)  // 404
```

Da bi probao pun tok, u `.env` postavi `OIDC_ENABLED=true` + `OIDC_*` parametre svog provajdera (npr.
Google), restartuj backend, pa na **Prijava** klikni „Prijava preko eksternog naloga (OIDC)".
✅ Posle uspešnog povratka sesija postoji, ali **vault je i dalje zaključan** — UI traži master lozinku
(OIDC daje samo sesiju; zero-knowledge očuvan).

---

## 10. Rate limiting i IP guard (gateway)

Preduslov: Redis je pokrenut.

### 10.1 Rate limit na login toku → 429

🧪 U konzoli (ili PowerShell) pošalji brzi niz zahteva:
```js
let codes = [];
for (let i = 0; i < 25; i++) {
  const r = await fetch('http://localhost:8080/api/auth/login/params', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ username:'nobody' })
  });
  codes.push(r.status);
}
console.log(codes.join(','));
```
✅ Posle „burst" kapaciteta pojavljuje se **429** (Too Many Requests).

### 10.2 Sumnjiv unos (SQLi/payload) → IP blok + security_event

🧪 Pošalji nekoliko zahteva sa SQLi uzorkom u query-ju (gateway `IpGuardFilter` ih broji):
```js
for (let i = 0; i < 8; i++) {
  await fetch("http://localhost:8080/api/vault/secrets?q=" + encodeURIComponent("' OR '1'='1"), {credentials:'include'});
}
```
✅ Posle praga (`IPGUARD_MAX_STRIKES`, default 5) IP je privremeno blokiran → naredni zahtevi **429**.

🗄️ Provera događaja:
```sql
SELECT type, ip, detail, created_at FROM security_event
WHERE type = 'IP_BLOCKED' ORDER BY created_at DESC LIMIT 5;
```
✅ Postoji red `IP_BLOCKED`. (Blok traje `IPGUARD_BLOCK_TTL_SEC`, default 300 s — sačekaj ili obriši
ključ iz Redisa da nastaviš.)

---

## 11. Honeypot i honeytokens (detekcija upada)

### 11.1 Ranjivi SQLi endpoint (admin ga pali)

1. 🌐 Kao **ADMIN** (`bob`) na **Admin** strani uključi **„Honeypot test-endpoint uključen"** → sačuvaj
   politiku. (Ili 🗄️ `UPDATE security_policy SET honeypot_endpoint = true WHERE is_active = true;`)
2. 🌐 Prijavi se kao **žrtva** `carol` (običan aktivan nalog). U njenoj konzoli pošalji SQLi payload:
   ```js
   await fetch("http://localhost:8080/api/honeypot/search?label=" + encodeURIComponent("' OR '1'='1' --"),
     {credentials:'include'}).then(r=>r.json())
   ```
   ✅ Vraća listu honeytokena (SQLi je „uspeo") — i time okida alarm na pozivaocu.
3. 🗄️ Provera posledica:
   ```sql
   SELECT username, status FROM users WHERE username = 'carol';                  -- FROZEN
   SELECT type, user_id, created_at FROM security_event
   WHERE type = 'HONEYPOT_HIT' ORDER BY created_at DESC LIMIT 3;                  -- nov red
   ```
   ✅ `carol` je sada **FROZEN**; postoji `HONEYPOT_HIT` događaj; u logu backenda je WARN admin-alarm.
4. 🌐 `carol` više ne može da se prijavi (**403** u prvom koraku). (Admin je može vratiti: status →
   `ACTIVE`.)

### 11.2 Dokaz: isključen endpoint → 404

1. 🌐/🗄️ Isključi `honeypot_endpoint` (Admin checkbox ili `UPDATE ... SET honeypot_endpoint=false`).
2. 🧪 Ponovi poziv iz 11.1 (kao bilo koji prijavljen korisnik).
   ✅ Vraća **404** (endpoint „ne postoji" dok ga admin ne upali).

> Napomena: pravi okidač radi i kad je endpoint ugašen — **svaki** direktan pristup honeytoken-tajni
> kroz regularni vault API (`GET/PUT/DELETE/share/rotate`) zamrzava nalog. (Za taj scenario treba
> 🗄️ ubaciti `secrets` red sa `is_honeytoken=true` + `secret_access` red za žrtvu, pa ga otvoriti.)

---

## 12. Imutabilni audit log (hash lanac + anchoring)

Preduslov: prijavljen kao **ADMIN** (`bob`).

### 12.1 Verifikacija netaknutog lanca

🧪
```js
await fetch('http://localhost:8080/api/admin/audit/verify', {credentials:'include'}).then(r=>r.json())
```
✅ `{ "valid": true, "verifiedCount": N, "brokenAtSeq": null }`.

### 12.2 Tiha izmena u bazi → lanac puca

1. 🗄️ Pokvari jedan stari zapis (zaobilazeći API):
   ```sql
   SELECT seq, action FROM audit_log ORDER BY seq LIMIT 5;       -- izaberi neki seq, npr. 2
   UPDATE audit_log SET metadata = '{"tampered":true}'::jsonb WHERE seq = 2;
   ```
2. 🧪 Ponovi verifikaciju iz 12.1.
   ✅ `{ "valid": false, "brokenAtSeq": 2 }` — lanac je otkrio izmenu od tog `seq` nadalje.
3. 🗄️ (Vrati original ako želiš čist lanac — postavi prethodni `metadata`.)

### 12.3 Sidrenje (anchoring) vrha lanca

🧪
```js
await fetch('http://localhost:8080/api/admin/audit/anchor', {method:'POST', credentials:'include'})
  .then(r=>r.status)
```
✅ **201** (ili **404** ako nema novih zapisa od poslednjeg sidra).
🗄️ `SELECT from_seq, to_seq, left(head_hash,12) AS head, channel FROM audit_anchor ORDER BY created_at DESC LIMIT 3;`
✅ Nov red sa `head_hash`-om (kanal „log" bez konfigurisanog mail-a).

### 12.4 Dokaz: append-only (nema UPDATE/DELETE ruta)

🧪
```js
await fetch('http://localhost:8080/api/admin/audit/log/anything', {method:'DELETE', credentials:'include'}).then(r=>r.status) // 404
```
✅ **404** — ruta ne postoji; audit se ne može menjati ni brisati kroz API. (Developer na
`/admin/audit/verify` dobija **403**, neautentikovan **401**.)

---

## 13. Hardening (Faza 12): sigurnosna zaglavlja, CORS, validacija konfiguracije

### 13.1 Sigurnosna HTTP zaglavlja

🧪 PowerShell (vidi sva zaglavlja proxy odgovora):
```powershell
(Invoke-WebRequest http://localhost:8080/api/health -UseBasicParsing).Headers
```
✅ Prisutni: `Content-Security-Policy: default-src 'none'; ...`, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy: ...`.

### 13.2 Striktan CORS

🧪 Preflight sa **dozvoljenog** origin-a → prolazi; sa **stranog** → odbijen:
```powershell
# dozvoljen (frontend) — vraća Access-Control-Allow-Origin = http://localhost:5173
(Invoke-WebRequest -Method Options http://localhost:8080/api/health -Headers @{Origin='http://localhost:5173';'Access-Control-Request-Method'='POST'} -UseBasicParsing).Headers['Access-Control-Allow-Origin']

# stran origin — NEMA Access-Control-Allow-Origin za evil.example (preflight odbijen)
try { Invoke-WebRequest -Method Options http://localhost:8080/api/health -Headers @{Origin='http://evil.example';'Access-Control-Request-Method'='POST'} -UseBasicParsing } catch { $_.Exception.Response.StatusCode.value__ }
```
✅ Prvi vraća `http://localhost:5173`; drugi je odbijen (403 / bez ACAO za stran origin).

### 13.3 Sve odjednom — demo skripta

🧪 Iz root-a projekta:
```powershell
./demo.ps1
# ako PowerShell blokira skripte:
powershell -ExecutionPolicy Bypass -File .\demo.ps1
```
✅ Niz `[PASS]` provera (health, zaglavlja, CORS, 401 na privatnim endpointima, 429 rate-limit) i
rezime `N PASS / 0 FAIL`.

### 13.4 Validacija konfiguracije na startu (fail-fast)

- **Dev (podrazumevano):** u logu backenda/gateway-a na startu vidiš `WARN [config] ...` za nesigurne
  dev tajne (npr. „JWT_SECRET koristi nesigurnu dev podrazumevanu vrednost") — ali se servis **podiže**.
- **Prod profil:** pokreni sa dev tajnama i `prod` profilom → servis **odbija** da se podigne:
  ```powershell
  $env:SPRING_PROFILES_ACTIVE = "prod"
  mvn -f backend/pom.xml spring-boot:run
  ```
  ✅ Start puca sa jasnom porukom „Neispravna/nesigurna konfiguracija — app neće biti pokrenut: …".
  (Vrati: `Remove-Item Env:\SPRING_PROFILES_ACTIVE` ili novi terminal.)

---

## Dodatak A — pgAdmin / psql „cheat-sheet"

```sql
-- Korisnici i njihovi UUID-ovi/uloge/statusi
SELECT id, username, email, role, status, created_at FROM users ORDER BY created_at;

-- Promovisanje uloge (pa OBAVEZNO re-login)
UPDATE users SET role = 'TEAM_LEAD' WHERE username = 'alice';   -- ili 'ADMIN' / 'DEVELOPER'

-- Reaktivacija zamrznutog/deaktiviranog naloga
UPDATE users SET status = 'ACTIVE' WHERE username = 'carol';

-- Tajne i pristupi (server vidi samo šifrat)
SELECT s.id, s.name, s.is_honeytoken, s.rotation_days, s.rotated_at,
       length(s.encrypted_blob) AS blob_bytes
FROM secrets s JOIN users u ON u.id = s.owner_id WHERE u.username = 'alice';

SELECT u.username, length(sa.wrapped_secret_key) AS wrapped_bytes
FROM secret_access sa JOIN users u ON u.id = sa.user_id WHERE sa.secret_id = '<SECRET_UUID>';

-- Sigurnosna politika (jedan aktivan red)
SELECT * FROM security_policy WHERE is_active = true;
UPDATE security_policy SET honeypot_endpoint = true WHERE is_active = true;

-- Honeytokeni (mamci — nevidljivi regularnom API-ju)
SELECT id, label FROM honeytoken;

-- Sigurnosni događaji (alarmi)
SELECT type, user_id, ip, detail, created_at FROM security_event ORDER BY created_at DESC LIMIT 20;

-- Audit lanac (append-only)
SELECT seq, action, resource, left(hash, 12) AS hash12, created_at
FROM audit_log ORDER BY seq;

-- „Isteknuta" rotacija za test upozorenja
UPDATE secrets SET rotated_at = now() - interval '400 days' WHERE name = 'API token';
```

> ⚠️ SQL `UPDATE`/`DELETE` nad `audit_log` koristi se **samo** da se DEMONSTRIRA da hash-lanac otkrije
> izmenu (§ 12.2) — u realnom radu nikad se ne dira. Nad ostalim tabelama (`users`, `security_policy`,
> `secrets`) SQL koristimo za pripremu test-scenarija koje API namerno ne izlaže (uloge, honeypot flag,
> rok rotacije).

---

## Brza mapa: funkcionalnost → gde se testira

| Funkcionalnost | Faza | Sekcija |
|---|---|---|
| Registracija + zero-knowledge skladištenje | 3 | § 1 |
| Lozinka + TOTP MFA + sesije/kolačići | 4 | § 2 |
| OIDC prijava (opciono) | 5 | § 9 |
| Vault CRUD (klijentska kripto) | 6 | § 3 |
| Sigurno deljenje (envelope) | 7 | § 5 |
| Admin status + politike | 8 | § 6 |
| Promena master lozinke | 8 | § 7 |
| Rotacija tajne | 8 | § 8 |
| Rate limiting + IP guard | 9 | § 10 |
| Honeypot + honeytokens (SQLi demo) | 10 | § 11 |
| Imutabilni audit (hash lanac + anchoring) | 11 | § 12 |
| Sigurnosna zaglavlja + CORS + validacija konfiguracije | 12 | § 13 |
