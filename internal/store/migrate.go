package store

import (
	"context"
	"embed"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// migrate applies the numbered files under migrations/ that are not yet in
// schema_migrations, each in its own transaction, under an advisory lock so
// replicas starting together do not race.
func migrate(ctx context.Context, db *pgxpool.Pool) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	conn, err := db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `select pg_advisory_lock(7206348)`); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `select pg_advisory_unlock(7206348)`)

	if _, err := conn.Exec(ctx, `
		create table if not exists schema_migrations (
			version    text primary key,
			applied_at timestamptz not null default now()
		)`); err != nil {
		return err
	}
	for _, name := range names {
		var applied bool
		if err := conn.QueryRow(ctx, `select exists (select 1 from schema_migrations where version = $1)`, name).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `insert into schema_migrations (version) values ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}
