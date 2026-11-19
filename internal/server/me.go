package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/noi-techpark/opendatahub-iam/internal/grants"
	"github.com/noi-techpark/opendatahub-iam/internal/store"
	"github.com/noi-techpark/opendatahub-iam/internal/token"
)

const (
	maxActiveTokens = 50
	maxExpiryDays   = 3650
	maxNamespaces   = 32
	maxDataBytes    = 64 << 10
)

var namespacePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

type roleView struct {
	Name      string `json:"name"`
	Inherited bool   `json:"inherited"`
}

type apiView struct {
	ClientID string     `json:"clientId"`
	Label    string     `json:"label"`
	Roles    []roleView `json:"roles"`
}

type meView struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`
	Name     string    `json:"name"`
	APIs     []apiView `json:"apis"`
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, err := s.dir.identity(r.Context(), sess.Subject, false)
	if err != nil {
		internalError(w, r, err)
		return
	}
	view := meView{
		ID:       sess.Subject,
		Username: id.User.Username,
		Email:    id.User.Email,
		Name:     strings.TrimSpace(id.User.FirstName + " " + id.User.LastName),
	}
	for _, api := range s.cfg.APIClients {
		roles := slices.Clone(id.Roles[api.ClientID])
		sort.Strings(roles)
		a := apiView{ClientID: api.ClientID, Label: api.Label, Roles: []roleView{}}
		for _, role := range roles {
			a.Roles = append(a.Roles, roleView{role, s.rules.IsInherited(role)})
		}
		view.APIs = append(view.APIs, a)
	}
	writeJSON(w, http.StatusOK, view)
}

type tokenView struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Grants     grants.Grants `json:"grants"`
	Effective  grants.Roles  `json:"effective"`
	CreatedAt  time.Time     `json:"createdAt"`
	ExpiresAt  *time.Time    `json:"expiresAt"`
	LastUsedAt *time.Time    `json:"lastUsedAt"`
	Expired    bool          `json:"expired"`
}

func (s *Server) tokenView(t store.Token, held grants.Roles) tokenView {
	return tokenView{
		ID:         t.ID,
		Name:       t.Name,
		Grants:     t.Grants,
		Effective:  s.rules.Effective(t.Grants, held),
		CreatedAt:  t.CreatedAt,
		ExpiresAt:  t.ExpiresAt,
		LastUsedAt: t.LastUsedAt,
		Expired:    t.Expired(time.Now()),
	}
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, err := s.dir.identity(r.Context(), sess.Subject, false)
	if err != nil {
		internalError(w, r, err)
		return
	}
	tokens, err := s.store.ActiveTokens(r.Context(), sess.Subject)
	if err != nil {
		internalError(w, r, err)
		return
	}
	out := make([]tokenView, len(tokens))
	for i, t := range tokens {
		out[i] = s.tokenView(t, id.Roles)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	var in struct {
		Name          string        `json:"name"`
		Grants        grants.Grants `json:"grants"`
		ExpiresInDays *int          `json:"expiresInDays"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxDataBytes)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "The request body is not valid JSON.")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		writeError(w, http.StatusBadRequest, "invalid_name", "Give the token a name of at most 64 characters.")
		return
	}
	var expiresAt *time.Time
	if in.ExpiresInDays != nil {
		if *in.ExpiresInDays < 1 || *in.ExpiresInDays > maxExpiryDays {
			writeError(w, http.StatusBadRequest, "invalid_expiry", "Expiry must be between 1 and 3650 days.")
			return
		}
		at := time.Now().Add(time.Duration(*in.ExpiresInDays) * 24 * time.Hour)
		expiresAt = &at
	}

	// Validate against Keycloak directly: a role granted seconds ago must be
	// selectable, and one just removed must not be.
	id, err := s.dir.identity(r.Context(), sess.Subject, true)
	if err != nil {
		internalError(w, r, err)
		return
	}
	allowed, err := s.rules.Normalize(in.Grants, id.Roles)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_grants", err.Error())
		return
	}

	existing, err := s.store.ActiveTokens(r.Context(), sess.Subject)
	if err != nil {
		internalError(w, r, err)
		return
	}
	if len(existing) >= maxActiveTokens {
		writeError(w, http.StatusConflict, "too_many_tokens", "Revoke a token before creating another.")
		return
	}

	tokenID, secret, hash := token.New()
	created, err := s.store.CreateToken(r.Context(), store.Token{
		ID: tokenID, UserID: sess.Subject, Name: in.Name, SecretHash: hash, Grants: allowed, ExpiresAt: expiresAt,
	})
	if errors.Is(err, store.ErrNameTaken) {
		writeError(w, http.StatusConflict, "name_taken", "You already have a token with that name.")
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":  s.tokenView(created, id.Roles),
		"secret": secret,
	})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	err := s.store.RevokeToken(r.Context(), sessionFrom(r).Subject, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "No such token.")
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listData(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.Data(r.Context(), sessionFrom(r).Subject, nil)
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, data)
}

func namespace(w http.ResponseWriter, r *http.Request) (string, bool) {
	ns := r.PathValue("namespace")
	if !namespacePattern.MatchString(ns) {
		writeError(w, http.StatusBadRequest, "invalid_namespace",
			"A namespace starts with a lowercase letter and contains only a-z, 0-9, '_', '.', '-'.")
		return "", false
	}
	return ns, true
}

func (s *Server) getData(w http.ResponseWriter, r *http.Request) {
	ns, ok := namespace(w, r)
	if !ok {
		return
	}
	data, err := s.store.Data(r.Context(), sessionFrom(r).Subject, []string{ns})
	if err != nil {
		internalError(w, r, err)
		return
	}
	value, found := data[ns]
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "Nothing stored under that namespace.")
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) getUserData(w http.ResponseWriter, r *http.Request) {
	ns, ok := namespace(w, r)
	if !ok {
		return
	}
	data, err := s.store.Data(r.Context(), r.PathValue("subject"), []string{ns})
	if err != nil {
		internalError(w, r, err)
		return
	}
	value, found := data[ns]
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "Nothing stored under that namespace.")
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) putData(w http.ResponseWriter, r *http.Request) {
	ns, ok := namespace(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDataBytes+1))
	if err != nil || len(body) > maxDataBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "A namespace holds at most 64 KiB.")
		return
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "The body must be a JSON object.")
		return
	}

	user := sessionFrom(r).Subject
	existing, err := s.store.Data(r.Context(), user, []string{ns})
	if err != nil {
		internalError(w, r, err)
		return
	}
	if _, replacing := existing[ns]; !replacing {
		n, err := s.store.CountData(r.Context(), user)
		if err != nil {
			internalError(w, r, err)
			return
		}
		if n >= maxNamespaces {
			writeError(w, http.StatusConflict, "too_many_namespaces", "Delete a namespace before adding another.")
			return
		}
	}
	if err := s.store.PutData(r.Context(), user, ns, body); err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, json.RawMessage(body))
}

func (s *Server) deleteData(w http.ResponseWriter, r *http.Request) {
	ns, ok := namespace(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteData(r.Context(), sessionFrom(r).Subject, ns); err != nil {
		internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
