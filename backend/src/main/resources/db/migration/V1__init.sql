-- Faza 1 — Inicijalna šema (DDL iz DEVELOPMENT_PLAN.md sekcija 3.2).
-- Flyway je vlasnik šeme; JPA entiteti se mapiraju na ove tabele (snake_case,
-- byte[] <-> bytea, enum <-> varchar preko @Enumerated(EnumType.STRING)).
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
