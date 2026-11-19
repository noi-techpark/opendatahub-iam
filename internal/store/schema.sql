create table if not exists users (
    id           text primary key,
    username     text not null,
    email        text not null default '',
    created_at   timestamptz not null default now(),
    last_seen_at timestamptz not null default now()
);

create table if not exists user_data (
    user_id    text not null references users (id) on delete cascade,
    namespace  text not null,
    data       jsonb not null,
    updated_at timestamptz not null default now(),
    primary key (user_id, namespace)
);

create table if not exists api_tokens (
    id           text primary key,
    user_id      text not null references users (id) on delete cascade,
    name         text not null,
    secret_hash  bytea not null,
    grants       jsonb not null,
    created_at   timestamptz not null default now(),
    expires_at   timestamptz,
    revoked_at   timestamptz,
    last_used_at timestamptz
);

create unique index if not exists api_tokens_active_name
    on api_tokens (user_id, name) where revoked_at is null;
