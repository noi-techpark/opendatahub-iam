package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/noi-techpark/opendatahub-iam/internal/grants"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrNameTaken = errors.New("name taken")
)

type Store struct{ db *pgxpool.Pool }

type Token struct {
	ID         string
	UserID     string
	Name       string
	SecretHash []byte
	Grants     grants.Grants
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

func (t Token) Expired(now time.Time) bool {
	return t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)
}

// Options bound the pool. Zero values keep pgx defaults.
type Options struct {
	MaxConns int32
	// StatementTimeout is enforced by Postgres on every statement, so a
	// stuck query cannot hold the hook path.
	StatementTimeout time.Duration
}

// Open connects, applies pending migrations and returns the store.
func Open(ctx context.Context, url string, opts Options) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	if opts.StatementTimeout > 0 {
		cfg.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprint(opts.StatementTimeout.Milliseconds())
	}
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() { s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.Ping(ctx) }

// UpsertUser records a Keycloak user the first time this service meets them
// and keeps the copied attributes current.
func (s *Store) UpsertUser(ctx context.Context, id, username, email string) error {
	_, err := s.db.Exec(ctx, `
		insert into users (id, username, email) values ($1, $2, $3)
		on conflict (id) do update
		set username = excluded.username, email = excluded.email, last_seen_at = now()`,
		id, username, email)
	return err
}

const tokenColumns = `id, user_id, name, secret_hash, grants, created_at, expires_at, revoked_at, last_used_at`

func scanToken(row pgx.Row) (Token, error) {
	var t Token
	var raw []byte
	err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.SecretHash, &raw,
		&t.CreatedAt, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, err
	}
	return t, json.Unmarshal(raw, &t.Grants)
}

func (s *Store) CreateToken(ctx context.Context, t Token) (Token, error) {
	raw, err := json.Marshal(t.Grants)
	if err != nil {
		return t, err
	}
	created, err := scanToken(s.db.QueryRow(ctx, `
		insert into api_tokens (id, user_id, name, secret_hash, grants, expires_at)
		values ($1, $2, $3, $4, $5, $6)
		returning `+tokenColumns,
		t.ID, t.UserID, t.Name, t.SecretHash, raw, t.ExpiresAt))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return t, ErrNameTaken
	}
	return created, err
}

func (s *Store) Token(ctx context.Context, id string) (Token, error) {
	return scanToken(s.db.QueryRow(ctx, `select `+tokenColumns+` from api_tokens where id = $1`, id))
}

func (s *Store) ActiveTokens(ctx context.Context, userID string) ([]Token, error) {
	rows, err := s.db.Query(ctx, `
		select `+tokenColumns+` from api_tokens
		where user_id = $1 and revoked_at is null
		order by created_at desc`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) RevokeToken(ctx context.Context, userID, id string) error {
	tag, err := s.db.Exec(ctx, `
		update api_tokens set revoked_at = now()
		where id = $1 and user_id = $2 and revoked_at is null`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchToken is throttled so a busy token does not write on every request.
func (s *Store) TouchToken(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `
		update api_tokens set last_used_at = now()
		where id = $1 and (last_used_at is null or last_used_at < now() - interval '1 minute')`, id)
	return err
}

func (s *Store) Data(ctx context.Context, userID string, namespaces []string) (map[string]json.RawMessage, error) {
	query := `select namespace, data from user_data where user_id = $1`
	args := []any{userID}
	if namespaces != nil {
		query += ` and namespace = any($2)`
		args = append(args, namespaces)
	}
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var ns string
		var data []byte
		if err := rows.Scan(&ns, &data); err != nil {
			return nil, err
		}
		out[ns] = data
	}
	return out, rows.Err()
}

func (s *Store) PutData(ctx context.Context, userID, namespace string, data json.RawMessage) error {
	_, err := s.db.Exec(ctx, `
		insert into user_data (user_id, namespace, data) values ($1, $2, $3)
		on conflict (user_id, namespace) do update set data = excluded.data, updated_at = now()`,
		userID, namespace, []byte(data))
	return err
}

func (s *Store) DeleteData(ctx context.Context, userID, namespace string) error {
	_, err := s.db.Exec(ctx, `delete from user_data where user_id = $1 and namespace = $2`, userID, namespace)
	return err
}

func (s *Store) CountData(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `select count(*) from user_data where user_id = $1`, userID).Scan(&n)
	return n, err
}

// RevokeAnyToken revokes a token whoever owns it and returns it, for the
// audit trail of an operator action.
func (s *Store) RevokeAnyToken(ctx context.Context, id string) (Token, error) {
	return scanToken(s.db.QueryRow(ctx, `
		update api_tokens set revoked_at = now()
		where id = $1 and revoked_at is null
		returning `+tokenColumns, id))
}
