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
	"github.com/noi-techpark/opendatahub-iam/internal/config"
	"github.com/noi-techpark/opendatahub-iam/internal/issuer"
	"github.com/noi-techpark/opendatahub-iam/internal/keycloak"
	"github.com/noi-techpark/opendatahub-iam/internal/server"
	"github.com/noi-techpark/opendatahub-iam/internal/store"
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

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Postgres may still be starting when the stack comes up together.
	var st *store.Store
	for attempt := 1; ; attempt++ {
		if st, err = store.Open(ctx, cfg.DatabaseURL); err == nil {
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

	iss, err := issuer.New(cfg.PublicURL, cfg.SigningKeyFile)
	if err != nil {
		return err
	}
	ui, err := fs.Sub(iam.Web, "web")
	if err != nil {
		return err
	}

	srv := server.New(cfg, st,
		keycloak.NewVerifier(ctx, cfg.KeycloakURL, cfg.KeycloakRealm, cfg.KeycloakIssuer, cfg.SessionAudience),
		keycloak.NewAdmin(cfg.KeycloakURL, cfg.KeycloakRealm, cfg.KeycloakClientID, cfg.KeycloakClientSecret),
		iss, ui)

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
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
