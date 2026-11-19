package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/noi-techpark/opendatahub-go-sdk/tel/logger"
	"github.com/noi-techpark/opendatahub-go-sdk/tel/stdhttp"
	"github.com/noi-techpark/opendatahub-iam/internal/config"
	"github.com/noi-techpark/opendatahub-iam/internal/directory"
	"github.com/noi-techpark/opendatahub-iam/internal/grants"
	"github.com/noi-techpark/opendatahub-iam/internal/issuer"
	"github.com/noi-techpark/opendatahub-iam/internal/keycloak"
	"github.com/noi-techpark/opendatahub-iam/internal/ratelimit"
	"github.com/noi-techpark/opendatahub-iam/internal/store"
	"github.com/noi-techpark/opendatahub-iam/internal/token"
)

type Server struct {
	cfg      config.Config
	store    *store.Store
	sessions *keycloak.Verifier
	dir      *directory.Directory
	issuer   *issuer.Issuer
	rules    grants.Rules
	ui       fs.FS
	// Brokers client_credentials requests to Keycloak.
	http  *http.Client
	limit *ratelimit.Limiter
}

func New(cfg config.Config, st *store.Store, sessions *keycloak.Verifier, dir *directory.Directory, iss *issuer.Issuer, ui fs.FS) *Server {
	clients := cfg.APIClientIDs()
	return &Server{
		cfg:      cfg,
		store:    st,
		sessions: sessions,
		dir:      dir,
		issuer:   iss,
		rules:    grants.Rules{Clients: clients, Inherited: cfg.InheritedRoles},
		ui:       ui,
		http:     &http.Client{Timeout: 30 * time.Second, Transport: stdhttp.Transport(nil)},
		limit:    ratelimit.New(cfg.RateLimitPerMinute),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("GET /ui/config.json", s.uiConfig)

	// Per-client budget on what relays credentials or writes on behalf of a
	// browser; the hook and the service-keyed routes stay unthrottled.
	limited := s.limit.Middleware(stdhttp.ClientIP, func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests; slow down.")
	})
	self := func(next http.HandlerFunc) http.Handler { return limited(s.session(next)) }
	mux.Handle("GET /v1/me", self(s.me))
	mux.Handle("GET /v1/me/tokens", self(s.listTokens))
	mux.Handle("POST /v1/me/tokens", self(s.createToken))
	mux.Handle("DELETE /v1/me/tokens/{id}", self(s.revokeToken))
	mux.Handle("GET /v1/me/data", self(s.listData))
	mux.Handle("GET /v1/me/data/{namespace}", self(s.getData))
	mux.Handle("PUT /v1/me/data/{namespace}", self(s.putData))
	mux.Handle("DELETE /v1/me/data/{namespace}", self(s.deleteData))

	mux.Handle("POST /v1/token", limited(http.HandlerFunc(s.clientToken)))
	mux.Handle("GET /v1/admin/users/{user}/tokens", limited(s.operator(s.listUserTokens)))
	mux.Handle("DELETE /v1/admin/tokens/{id}", limited(s.operator(s.operatorRevoke)))
	mux.HandleFunc("POST /v1/resolve", s.service(s.resolve))
	mux.HandleFunc("GET /v1/users/{subject}/data/{namespace}", s.service(s.getUserData))
	mux.HandleFunc("GET /v1/forward-auth/{service}", s.forwardAuth)

	mux.Handle("GET /", s.console())
	return instrument(mux)
}

// console serves the embedded UI. The page handles session tokens and freshly
// created API tokens, so it may only talk to this service, Keycloak and the
// demo API.
func (s *Server) console() http.Handler {
	connect := []string{"'self'"}
	for _, raw := range []string{s.cfg.KeycloakIssuer, s.cfg.DemoAPIURL} {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			connect = append(connect, u.Scheme+"://"+u.Host)
		}
	}
	policy := "default-src 'self'; connect-src " + strings.Join(connect, " ") +
		"; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
	files := http.FileServerFS(s.ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", policy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
}

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apiError{code, message})
}

func internalError(w http.ResponseWriter, r *http.Request, err error) {
	logger.Get(r.Context()).Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.")
}

func bearer(r *http.Request) string {
	scheme, value, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

type sessionKey struct{}

// session guards the self-service endpoints. They take an interactive
// Keycloak login only: an API token must not be able to mint further tokens
// or read its owner's private data.
func (s *Server) session(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := bearer(r)
		switch {
		case raw == "":
			writeError(w, http.StatusUnauthorized, "missing_token", "Sign in first.")
			return
		case token.Looks(raw):
			writeError(w, http.StatusForbidden, "session_required", "API tokens cannot manage the account; sign in interactively.")
			return
		}
		sess, err := s.sessions.Verify(r.Context(), raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_token", "The session is invalid or expired.")
			return
		}
		if err := s.store.UpsertUser(r.Context(), sess.Subject, sess.Username, sess.Email); err != nil {
			internalError(w, r, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)))
	}
}

func sessionFrom(r *http.Request) keycloak.Session {
	return r.Context().Value(sessionKey{}).(keycloak.Session)
}

type serviceKey struct{}

func (s *Server) service(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := bearer(r)
		match := s.serviceByKey(key)
		if key == "" || match == nil {
			writeError(w, http.StatusUnauthorized, "invalid_service_key", "A valid service key is required.")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), serviceKey{}, match)))
	}
}

// serviceByKey compares against every configured key, so timing does not
// tell which service a guess was close to.
func (s *Server) serviceByKey(key string) *config.Service {
	var match *config.Service
	for i := range s.cfg.Services {
		svc := &s.cfg.Services[i]
		if subtle.ConstantTimeCompare([]byte(key), []byte(svc.Key)) == 1 {
			match = svc
		}
	}
	return match
}

func serviceFrom(r *http.Request) *config.Service {
	return r.Context().Value(serviceKey{}).(*config.Service)
}

// health is liveness: the process serves requests.
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ready is readiness: the database answers. Keycloak is deliberately not
// part of it; while it is down, cached identities still resolve.
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		logger.Get(r.Context()).Error("health check failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "The database does not answer.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// discovery lets standard OIDC resource-server libraries find the keys from
// the issuer URL alone. This service has no authorization endpoint.
func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.issuer.URL,
		"jwks_uri":                              s.issuer.URL + "/.well-known/jwks.json",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"subject_types_supported":               []string{"public"},
		"response_types_supported":              []string{"none"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(s.issuer.JWKS())
}

func (s *Server) uiConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":      s.cfg.KeycloakIssuer,
		"clientId":    s.cfg.UIClientID,
		"audience":    s.cfg.SessionAudience,
		"demoApiUrl":  s.cfg.DemoAPIURL,
		"tokenPrefix": token.Prefix,
	})
}
