//go:build e2e

// Package e2e runs against the docker-compose stack: a real Keycloak carrying
// the production UMA configuration, Postgres, the identity service and the
// demo resource servers.
package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var (
	kcURL   = env("E2E_KEYCLOAK_URL", "http://localhost:8180")
	iamURL  = env("E2E_IAM_URL", "http://localhost:4010")
	demoURL = env("E2E_DEMO_URL", "http://localhost:4011")
	dbURL   = env("E2E_DATABASE_URL", "postgres://iam:iam@localhost:5433/iam")

	// Upper bound for a change in Keycloak to cross the service cache. The
	// suite expects the stack started by `make e2e`.
	propagation = 20 * time.Second

	client = &http.Client{Timeout: 30 * time.Second}
)

const (
	realm = "noi"

	timeseriesKey = "dev-timeseries-service-key"
	contentKey    = "dev-content-service-key"
	parkingKey    = "dev-parking-service-key"

	mobility = "odh-mobility-v2"
	apiCore  = "odh-api-core"
	parking  = "opendatahub-parking-control-tower"
)

func TestMain(m *testing.M) {
	deadline := time.Now().Add(4 * time.Minute)
	for _, probe := range []string{
		kcURL + "/realms/" + realm + "/.well-known/openid-configuration",
		iamURL + "/healthz",
		demoURL + "/healthz",
	} {
		for {
			resp, err := client.Get(probe)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					break
				}
			}
			if time.Now().After(deadline) {
				fmt.Fprintf(os.Stderr, "stack not ready: %s\n", probe)
				os.Exit(1)
			}
			time.Sleep(2 * time.Second)
		}
	}
	os.Exit(m.Run())
}

type response struct {
	Status int
	Body   []byte
}

func (r response) decode(t *testing.T, into any) {
	t.Helper()
	if err := json.Unmarshal(r.Body, into); err != nil {
		t.Fatalf("decoding %q: %v", r.Body, err)
	}
}

func (r response) errorCode() string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(r.Body, &e)
	return e.Error
}

func call(t *testing.T, method, target, bearer string, body any) response {
	t.Helper()
	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		reader = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return response{resp.StatusCode, raw}
}

func wantStatus(t *testing.T, r response, status int) response {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status %d, want %d: %s", r.Status, status, r.Body)
	}
	return r
}

func eventually(t *testing.T, what string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(propagation)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatalf("did not happen within %s: %s", propagation, what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// --- Keycloak ---

func tokenRequest(t *testing.T, realmName string, form url.Values, bearer string) response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost,
		kcURL+"/realms/"+realmName+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return response{resp.StatusCode, raw}
}

func accessToken(t *testing.T, r response) string {
	t.Helper()
	wantStatus(t, r, http.StatusOK)
	var out struct {
		AccessToken string `json:"access_token"`
	}
	r.decode(t, &out)
	return out.AccessToken
}

// login returns a fresh session token, carrying the user's roles as of now.
func login(t *testing.T, username string) string {
	t.Helper()
	return accessToken(t, tokenRequest(t, realm, url.Values{
		"grant_type": {"password"}, "client_id": {"odh-iam-ui"},
		"username": {username}, "password": {username},
	}, ""))
}

type keycloakAdmin struct {
	t     *testing.T
	token string
}

func admin(t *testing.T) keycloakAdmin {
	t.Helper()
	return keycloakAdmin{t, accessToken(t, tokenRequest(t, "master", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {"admin"}, "password": {"admin"},
	}, ""))}
}

func (a keycloakAdmin) do(method, path string, body any, wantStatus int) response {
	a.t.Helper()
	r := call(a.t, method, kcURL+"/admin/realms/"+realm+path, a.token, body)
	if r.Status != wantStatus {
		a.t.Fatalf("keycloak %s %s: %d %s", method, path, r.Status, r.Body)
	}
	return r
}

func (a keycloakAdmin) userID(username string) string {
	a.t.Helper()
	var users []struct {
		ID string `json:"id"`
	}
	a.do("GET", "/users?exact=true&username="+url.QueryEscape(username), nil, 200).decode(a.t, &users)
	if len(users) != 1 {
		a.t.Fatalf("user %q not found", username)
	}
	return users[0].ID
}

func (a keycloakAdmin) rolePath(username, clientID string) (string, string) {
	a.t.Helper()
	var clients []struct {
		ID string `json:"id"`
	}
	a.do("GET", "/clients?clientId="+url.QueryEscape(clientID), nil, 200).decode(a.t, &clients)
	if len(clients) != 1 {
		a.t.Fatalf("client %q not found", clientID)
	}
	return clients[0].ID, "/users/" + a.userID(username) + "/role-mappings/clients/" + clients[0].ID
}

func (a keycloakAdmin) changeRoles(method, username, clientID string, roles []string) {
	a.t.Helper()
	uuid, path := a.rolePath(username, clientID)
	reps := []json.RawMessage{}
	for _, role := range roles {
		reps = append(reps, a.do("GET", "/clients/"+uuid+"/roles/"+url.PathEscape(role), nil, 200).Body)
	}
	a.do(method, path, reps, 204)
}

// grant gives roles for the duration of the test.
func (a keycloakAdmin) grant(username, clientID string, roles ...string) {
	a.t.Helper()
	a.changeRoles("POST", username, clientID, roles)
	a.t.Cleanup(func() { a.changeRoles("DELETE", username, clientID, roles) })
}

// withdraw removes roles for the duration of the test.
func (a keycloakAdmin) withdraw(username, clientID string, roles ...string) {
	a.t.Helper()
	a.changeRoles("DELETE", username, clientID, roles)
	a.t.Cleanup(func() { a.changeRoles("POST", username, clientID, roles) })
}

func (a keycloakAdmin) setEnabled(username string, enabled bool) {
	a.t.Helper()
	a.do("PUT", "/users/"+a.userID(username), map[string]any{"enabled": enabled}, 204)
}

// umaPermissions asks Keycloak itself, the way the content API does today.
func umaPermissions(t *testing.T, session string) map[string][]string {
	t.Helper()
	r := tokenRequest(t, realm, url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:uma-ticket"},
		"audience":      {"odh-tourism-api"},
		"response_mode": {"permissions"},
	}, session)
	if r.Status == http.StatusForbidden {
		return map[string][]string{}
	}
	wantStatus(t, r, http.StatusOK)
	var perms []permission
	r.decode(t, &perms)
	return byResource(perms)
}

// --- identity service ---

type permission struct {
	RsName string   `json:"rsname"`
	Scopes []string `json:"scopes"`
}

func byResource(perms []permission) map[string][]string {
	out := map[string][]string{}
	for _, p := range perms {
		scopes := append([]string{}, p.Scopes...)
		sort.Strings(scopes)
		out[p.RsName] = scopes
	}
	return out
}

type resolution struct {
	Active    bool   `json:"active"`
	Reason    string `json:"reason"`
	Principal struct {
		Kind      string `json:"kind"`
		Subject   string `json:"sub"`
		Username  string `json:"username"`
		TokenID   string `json:"tokenId"`
		TokenName string `json:"tokenName"`
	} `json:"principal"`
	Roles       map[string][]string     `json:"roles"`
	Permissions map[string][]permission `json:"permissions"`
	JWT         string                  `json:"jwt"`
	ExpiresIn   int                     `json:"expiresIn"`
}

func resolve(t *testing.T, serviceKey, credential string) resolution {
	t.Helper()
	body := map[string]any{"token": credential}
	var out resolution
	response := wantStatus(t, call(t, "POST", iamURL+"/v1/resolve", serviceKey, body), 200)
	var fields map[string]json.RawMessage
	response.decode(t, &fields)
	if _, exists := fields["data"]; exists {
		t.Fatal("resolution contains user data")
	}
	response.decode(t, &out)
	if out.JWT != "" {
		parts := strings.Split(out.JWT, ".")
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var claims map[string]json.RawMessage
		if err := json.Unmarshal(raw, &claims); err != nil {
			t.Fatal(err)
		}
		if _, exists := claims["odh_data"]; exists {
			t.Fatal("JWT contains user data")
		}
	}
	return out
}

type apiToken struct {
	ID     string
	Secret string
}

func createTokenRaw(t *testing.T, session, name string, grants map[string][]string) response {
	t.Helper()
	return call(t, "POST", iamURL+"/v1/me/tokens", session,
		map[string]any{"name": name, "grants": grants, "expiresInDays": 30})
}

// createToken makes a token that is revoked again when the test ends.
func createToken(t *testing.T, session, name string, grants map[string][]string) apiToken {
	t.Helper()
	var out struct {
		Secret string `json:"secret"`
		Token  struct {
			ID string `json:"id"`
		} `json:"token"`
	}
	name = fmt.Sprintf("%s %s %d", t.Name(), name, time.Now().UnixNano())
	if len(name) > 64 {
		name = name[len(name)-64:]
	}
	wantStatus(t, createTokenRaw(t, session, name, grants), 201).decode(t, &out)
	t.Cleanup(func() { call(t, "DELETE", iamURL+"/v1/me/tokens/"+out.Token.ID, session, nil) })
	return apiToken{out.Token.ID, out.Secret}
}

func db(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// --- demo resource servers ---

type demoCaller struct {
	Kind     string   `json:"kind"`
	Subject  string   `json:"sub"`
	Username string   `json:"username"`
	TokenID  string   `json:"tokenId"`
	Roles    []string `json:"roles"`
}

type datasetsView struct {
	Caller   demoCaller `json:"caller"`
	Quota    string     `json:"quota"`
	Datasets []string   `json:"datasets"`
}

func datasets(t *testing.T, bearer string) datasetsView {
	t.Helper()
	var out datasetsView
	wantStatus(t, call(t, "GET", demoURL+"/timeseries/datasets", bearer, nil), 200).decode(t, &out)
	return out
}
