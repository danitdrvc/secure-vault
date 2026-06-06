-- Faza 1 — Seed početnih podataka. Idempotentno (ponovno pokretanje ne puca).
-- VAŽNO (zero-knowledge): kripto polja admina su PLACEHOLDER (nasumični bajtovi)
-- samo da zadovolje NOT NULL. Prave vrednosti (auth_hash = bcrypt(authKey),
-- enc_usk, enc_private_key, public_key) nastaju na KLIJENTU tek u Fazi 3/4 —
-- server ih nikad ne generiše. Ovim placeholder-om se NE moze prijaviti.

-- Jedan ADMIN nalog.
insert into users (username, email, role, status,
                   kdf_salt, auth_hash,
                   enc_usk, public_key, enc_private_key)
values ('admin', 'admin@securevault.local', 'ADMIN', 'ACTIVE',
        gen_random_bytes(16),
        '$2a$10$PLACEHOLDERseedhashPLACEHOLDERseedhashPLACEHOLDERxx',  -- placeholder, NE pravi bcrypt
        gen_random_bytes(64),   -- placeholder enc_usk
        gen_random_bytes(64),   -- placeholder public_key (SPKI)
        gen_random_bytes(64))   -- placeholder enc_private_key
on conflict (username) do nothing;

-- Tačno jedna aktivna sigurnosna politika (svi defaulti iz V1 DDL-a).
insert into security_policy (is_active)
select true
where not exists (select 1 from security_policy);

-- Par honeytoken redova (mamci; izgledaju kao realni resursi).
insert into honeytoken (label, fake_blob)
select label, gen_random_bytes(48)
from (values
  ('AWS_PROD_ACCESS_KEY'),
  ('db-root-credentials'),
  ('stripe_live_secret_key')
) as seed(label)
where not exists (select 1 from honeytoken);
