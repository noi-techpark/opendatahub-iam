package server

import (
	"errors"
	"net/http"
	"slices"

	"github.com/noi-techpark/opendatahub-go-sdk/tel/logger"

	"github.com/noi-techpark/opendatahub-iam/internal/keycloak"
	"github.com/noi-techpark/opendatahub-iam/internal/store"
)

// operator admits a session whose Keycloak token carries the admin role on
// this service's own client. The role is read from the token, so a revoked
// operator keeps access until that token expires, as with any Keycloak role.
func (s *Server) operator(next http.HandlerFunc) http.HandlerFunc {
	return s.session(func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r)
		if !slices.Contains(sess.ResourceAccess[s.cfg.KeycloakClientID].Roles, s.cfg.AdminRole) {
			writeError(w, http.StatusForbidden, "operator_required", "This needs the "+s.cfg.AdminRole+" role.")
			return
		}
		next(w, r)
	})
}

// listUserTokens shows the active tokens of a user named by Keycloak id or
// username, as the owner would see them in the console.
func (s *Server) listUserTokens(w http.ResponseWriter, r *http.Request) {
	id, err := s.dir.Lookup(r.Context(), r.PathValue("user"))
	if errors.Is(err, keycloak.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "No such user.")
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	tokens, err := s.store.ActiveTokens(r.Context(), id.User.ID)
	if err != nil {
		internalError(w, r, err)
		return
	}
	out := make([]tokenView, len(tokens))
	for i, t := range tokens {
		out[i] = s.tokenView(t, id.Roles)
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": id.User, "tokens": out})
}

func (s *Server) operatorRevoke(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.RevokeAnyToken(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "No such active token.")
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	logger.Get(r.Context()).Info("token revoked by operator",
		"operator", sessionFrom(r).Subject, "token", t.ID, "owner", t.UserID)
	w.WriteHeader(http.StatusNoContent)
}
