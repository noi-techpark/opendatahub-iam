package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/noi-techpark/opendatahub-go-sdk/tel/logger"
	"github.com/noi-techpark/opendatahub-iam/internal/config"
	"github.com/noi-techpark/opendatahub-iam/internal/grants"
	"github.com/noi-techpark/opendatahub-iam/internal/keycloak"
	"github.com/noi-techpark/opendatahub-iam/internal/store"
	"github.com/noi-techpark/opendatahub-iam/internal/token"
	"github.com/noi-techpark/opendatahub-iam/internal/uma"
)

type principal struct {
	Azp       string   `json:"-"`
	Audience  []string `json:"-"`
	Kind      string   `json:"kind"`
	Subject   string   `json:"sub"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	TokenID   string   `json:"tokenId,omitempty"`
	TokenName string   `json:"tokenName,omitempty"`
}

type resolution struct {
	Active bool   `json:"active"`
	Reason string `json:"reason,omitempty"`

	Principal *principal   `json:"principal,omitempty"`
	Roles     grants.Roles `json:"roles,omitempty"`
	// Keyed by the Keycloak client that owns the UMA configuration.
	Permissions map[string][]uma.Permission `json:"permissions,omitempty"`
	JWT         string                      `json:"jwt,omitempty"`
	ExpiresIn   int                         `json:"expiresIn,omitempty"`
}

// errUnavailable is returned when a dependency, not the credential, failed.
type errUnavailable struct {
	code    string
	message string
	err     error
}

func (e *errUnavailable) Error() string { return e.err.Error() }

// resolve turns a credential a resource server received into the identity
// behind it: an API token or a Keycloak access token. Both yield the same
// resolution and the same signed JWT, so a resource server handles one
// issuer and one claim shape.
func (s *Server) resolve(w http.ResponseWriter, r *http.Request) {
	svc := serviceFrom(r)
	var in struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil || in.Token == "" {
		writeError(w, http.StatusBadRequest, "invalid_body", `Send {"token": "<credential>"}.`)
		return
	}
	out, err := s.resolveCredential(r, svc, in.Token)
	if err != nil {
		s.writeResolveError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// forwardAuth is the same resolution for an ingress hook (nginx auth_request,
// Traefik forwardAuth, Envoy ext_authz). The ingress copies the Authorization
// header of a 200 answer onto the request it forwards, so the resource server
// only ever sees JWTs signed by this service.
//
// The caller proves itself with X-Service-Key; inside a cluster the route
// should also be limited to the ingress by network policy.
func (s *Server) forwardAuth(w http.ResponseWriter, r *http.Request) {
	svc := s.serviceNamed(r.PathValue("service"))
	if svc == nil || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Service-Key")), []byte(svc.Key)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid_service_key", "Unknown service or key.")
		return
	}
	raw := bearer(r)
	if raw == "" {
		// Anonymous: nothing to swap, the resource server applies its own
		// default. An unparseable header is dropped the same way.
		w.Header().Set("Authorization", "")
		w.WriteHeader(http.StatusOK)
		return
	}
	out, err := s.resolveCredential(r, svc, raw)
	if err != nil {
		s.writeResolveError(w, r, err)
		return
	}
	if !out.Active {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+out.Reason+`"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "Credential rejected: "+out.Reason+".")
		return
	}
	w.Header().Set("Authorization", "Bearer "+out.JWT)
	w.Header().Set("X-Identity-Subject", out.Principal.Subject)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) serviceNamed(name string) *config.Service {
	for i := range s.cfg.Services {
		if s.cfg.Services[i].Name == name {
			return &s.cfg.Services[i]
		}
	}
	return nil
}

func (s *Server) writeResolveError(w http.ResponseWriter, r *http.Request, err error) {
	var unavailable *errUnavailable
	if errors.As(err, &unavailable) {
		logger.Get(r.Context()).Error(unavailable.code, "err", unavailable.err)
		writeError(w, http.StatusServiceUnavailable, unavailable.code, unavailable.message)
		return
	}
	internalError(w, r, err)
}

func (s *Server) resolveCredential(r *http.Request, svc *config.Service, raw string) (resolution, error) {
	if token.Looks(raw) {
		return s.resolveAPIToken(r, svc, raw)
	}
	if s.issuer.IsOwn(raw) {
		return s.resolveOwn(svc, raw), nil
	}
	return s.resolveSession(r, svc, raw)
}

func (s *Server) resolveAPIToken(r *http.Request, svc *config.Service, raw string) (resolution, error) {
	ctx := r.Context()
	id, secret, ok := token.Parse(raw)
	if !ok {
		return resolution{Reason: "malformed"}, nil
	}
	t, err := s.store.Token(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !token.Matches(secret, t.SecretHash)) {
		return resolution{Reason: "unknown"}, nil
	}
	if err != nil {
		return resolution{}, err
	}
	if t.RevokedAt != nil {
		return resolution{Reason: "revoked"}, nil
	}
	if t.Expired(time.Now()) {
		return resolution{Reason: "expired"}, nil
	}

	owner, err := s.dir.Identity(ctx, t.UserID, false)
	if errors.Is(err, keycloak.ErrNotFound) || (err == nil && !owner.User.Enabled) {
		return resolution{Reason: "owner_disabled"}, nil
	}
	if err != nil {
		return resolution{}, err
	}

	p := &principal{
		Azp: s.cfg.KeycloakClientID, Kind: "api_token", Subject: t.UserID, Username: owner.User.Username, Email: owner.User.Email,
		TokenID: t.ID, TokenName: t.Name,
	}
	out, err := s.issue(r, svc, p, s.rules.Effective(t.Grants, owner.Roles))
	if err != nil {
		return resolution{}, err
	}
	if err := s.store.TouchToken(ctx, t.ID); err != nil {
		logger.Get(ctx).Warn("could not record token use", "token", t.ID, "err", err)
	}
	return out, nil
}

// resolveSession re-reads the user from Keycloak rather than trusting the
// roles baked into the token, so a session and an API token of the same
// user see role changes with the same delay.
func (s *Server) resolveSession(r *http.Request, svc *config.Service, raw string) (resolution, error) {
	ctx := r.Context()
	sess, err := s.sessions.VerifyAnyAudience(ctx, raw)
	if err != nil {
		return resolution{Reason: "invalid"}, nil
	}
	if err := s.store.UpsertUser(ctx, sess.Subject, sess.Username, sess.Email); err != nil {
		return resolution{}, err
	}
	user, err := s.dir.Identity(ctx, sess.Subject, false)
	if errors.Is(err, keycloak.ErrNotFound) || (err == nil && !user.User.Enabled) {
		return resolution{Reason: "user_disabled"}, nil
	}
	if err != nil {
		return resolution{}, err
	}
	p := &principal{Azp: sess.Azp, Audience: sess.Audience, Kind: "session", Subject: sess.Subject, Username: user.User.Username, Email: user.User.Email}
	return s.issue(r, svc, p, user.Roles)
}

// issue builds the resolution for a principal that carries the given roles:
// the slice of roles this service sees, its UMA permissions, and its JWT.
func (s *Server) issue(r *http.Request, svc *config.Service, p *principal, carried grants.Roles) (resolution, error) {
	return s.issueServices(r, []config.Service{*svc}, p, carried, s.cfg.JWTTTL)
}

func (s *Server) issueServices(r *http.Request, services []config.Service, p *principal, carried grants.Roles, ttl time.Duration) (resolution, error) {
	ctx := r.Context()
	var clients, audiences []string
	audiences = append(audiences, p.Audience...)
	for _, svc := range services {
		clients = append(clients, svc.Clients...)
		audiences = slices.DeleteFunc(audiences, func(a string) bool { return a == svc.Audience })
		audiences = append(audiences, svc.Audience)
	}
	audiences = unique(audiences)
	out := resolution{
		Active:    true,
		Principal: p,
		Roles:     carried.Only(clients),
		ExpiresIn: int(ttl.Seconds()),
	}

	for _, svc := range services {
		if p.Kind == "client" && len(carried.Only(svc.Clients)) == 0 {
			continue
		}
		if len(svc.UMA) > 0 {
			if out.Permissions == nil {
				out.Permissions = map[string][]uma.Permission{}
			}
			has := func(roleID string) bool {
				client, role, _ := strings.Cut(roleID, "/")
				return slices.Contains(carried[client], role)
			}
			for _, client := range svc.UMA {
				evaluator, err := s.dir.Evaluator(ctx, client)
				if err != nil {
					// Fail closed: an unreadable or unsupported policy set must
					// not degrade into "no permissions" that looks deliberate.
					return resolution{}, &errUnavailable{"uma_unavailable",
						"The authorization configuration of " + client + " cannot be evaluated.", err}
				}
				out.Permissions[client] = evaluator.Permissions(has)
			}
		}
	}

	claims := map[string]any{
		"typ":                "Bearer",
		"azp":                p.Azp,
		"preferred_username": p.Username,
		"email":              p.Email,
		"resource_access":    resourceAccess(out.Roles),
		"odh_principal":      p.Kind,
	}
	if p.TokenID != "" {
		claims["odh_token_id"] = p.TokenID
	}
	for _, svc := range services {
		if f := svc.FlatRoleClaim; f != nil {
			claims[f.Claim] = append([]string{}, out.Roles[f.Client]...)
		}
	}
	if out.Permissions != nil {
		claims["odh_permissions"] = out.Permissions
	}
	var err error
	if out.JWT, err = s.issuer.Sign(p.Subject, audiences, ttl, claims); err != nil {
		return resolution{}, err
	}
	return out, nil
}

func resourceAccess(roles grants.Roles) map[string]any {
	out := map[string]any{}
	for client, names := range roles {
		out[client] = map[string]any{"roles": names}
	}
	return out
}

func unique(values []string) []string {
	out := []string{}
	for _, value := range values {
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out
}

func (s *Server) resolveOwn(svc *config.Service, raw string) resolution {
	var c struct {
		Kind           string `json:"odh_principal"`
		Username       string `json:"preferred_username"`
		Email          string `json:"email"`
		TokenID        string `json:"odh_token_id"`
		ResourceAccess map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
		Permissions map[string][]uma.Permission `json:"odh_permissions"`
	}
	registered, err := s.issuer.Verify(raw, &c)
	if err != nil {
		return resolution{Reason: "invalid"}
	}
	if !slices.Contains(registered.Audience, svc.Audience) {
		return resolution{Reason: "audience"}
	}
	roles := grants.Roles{}
	for _, client := range svc.Clients {
		if access, ok := c.ResourceAccess[client]; ok {
			roles[client] = access.Roles
		}
	}
	return resolution{Active: true, Principal: &principal{Kind: c.Kind, Subject: registered.Subject, Username: c.Username, Email: c.Email, TokenID: c.TokenID}, Roles: roles, Permissions: c.Permissions, JWT: raw, ExpiresIn: int(time.Until(registered.Expiry.Time()).Seconds())}
}
