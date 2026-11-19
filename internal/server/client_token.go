package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/noi-techpark/opendatahub-iam/internal/keycloak"
)

func (s *Server) clientToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		s.cfg.KeycloakURL+"/realms/"+s.cfg.KeycloakRealm+"/protocol/openid-connect/token", strings.NewReader(r.PostForm.Encode()))
	if err != nil {
		internalError(w, r, err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, 503, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		writeJSON(w, 502, map[string]string{"error": "server_error"})
		return
	}
	sess, err := s.sessions.VerifyAnyAudience(r.Context(), token.AccessToken)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "server_error"})
		return
	}
	user, err := s.dir.identity(r.Context(), sess.Subject, false)
	if errors.Is(err, keycloak.ErrNotFound) || (err == nil && !user.User.Enabled) {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	if err != nil {
		s.writeResolveError(w, r, err)
		return
	}
	p := &principal{Kind: "client", Subject: sess.Subject, Username: user.User.Username, Email: user.User.Email, Azp: sess.Azp, Audience: sess.Audience}
	out, err := s.issueServices(r, s.cfg.Services, p, user.Roles, s.cfg.ClientTokenTTL)
	if err != nil {
		s.writeResolveError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"access_token": out.JWT, "token_type": "Bearer", "expires_in": out.ExpiresIn})
}
