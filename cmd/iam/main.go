package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	iam "github.com/noi-techpark/opendatahub-iam"
	"github.com/noi-techpark/opendatahub-iam/internal/cache"
	"github.com/noi-techpark/opendatahub-iam/internal/config"
	"github.com/noi-techpark/opendatahub-iam/internal/directory"
	"github.com/noi-techpark/opendatahub-iam/internal/issuer"
	"github.com/noi-techpark/opendatahub-iam/internal/keycloak"
	"github.com/noi-techpark/opendatahub-iam/internal/obs"
	"github.com/noi-techpark/opendatahub-iam/internal/server"
	"github.com/noi-techpark/opendatahub-iam/internal/store"
	"github.com/noi-techpark/opendatahub-iam/internal/uma"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	flush, err := obs.Init(ctx, "odh-iam")
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		flush(ctx)
	}()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Postgres may still be starting when the stack comes up together.
	var st *store.Store
	for attempt := 1; ; attempt++ {
		if st, err = store.Open(ctx, cfg.DatabaseURL, store.Options{MaxConns: int32(cfg.DBMaxConns), StatementTimeout: cfg.DBStatementTimeout}); err == nil {
			break
		}
		if attempt == 30 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	defer st.Close()

	iss, err := issuer.New(cfg.PublicURL, cfg.SigningKeysDir)
	if err != nil {
		return err
	}
	ui, err := fs.Sub(iam.Web, "web")
	if err != nil {
		return err
	}

	// Per-replica caches for now; a shared cache.Cache goes here when the
	// replicas should see one view.
	dir := directory.New(
		keycloak.NewAdmin(cfg.KeycloakURL, cfg.KeycloakRealm, cfg.KeycloakClientID, cfg.KeycloakClientSecret),
		cfg.APIClientIDs(), cfg.CacheTTL, cfg.PolicyTTL,
		cache.NewMemory[directory.Identity](50_000), cache.NewMemory[*uma.Evaluator](16))
	srv := server.New(cfg, st,
		keycloak.NewVerifier(ctx, cfg.KeycloakURL, cfg.KeycloakRealm, cfg.KeycloakIssuer, cfg.SessionAudience),
		dir, iss, ui)

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// The token endpoint waits up to 30 s on Keycloak.
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()

	slog.Info("listening", "addr", cfg.Listen, "issuer", cfg.PublicURL, "keycloak", cfg.KeycloakIssuer)
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
