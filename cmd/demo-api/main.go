// demo-api stands in for the three Open Data Hub APIs. Each mini API keeps
// the authorization style of the real one. None of them knows Keycloak or
// API tokens: the ingress swaps every credential for a JWT signed by the
// identity service, and that is the only issuer verified here.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var (
	iamURL    = strings.TrimRight(env("IAM_URL", "http://localhost:4010"), "/")
	iamIssuer = env("IAM_ISSUER", iamURL)
)

type api struct {
	client   string
	verifier *oidc.IDTokenVerifier
}

type permission struct {
	RsName string   `json:"rsname"`
	Scopes []string `json:"scopes"`
}

type claims struct {
	Subject        string `json:"sub"`
	Username       string `json:"preferred_username"`
	Principal      string `json:"odh_principal"`
	TokenID        string `json:"odh_token_id"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
	Permissions map[string][]permission `json:"odh_permissions"`
}

type caller struct {
	Kind     string   `json:"kind"`
	Subject  string   `json:"sub,omitempty"`
	Username string   `json:"username,omitempty"`
	TokenID  string   `json:"tokenId,omitempty"`
	Roles    []string `json:"roles"`

	claims claims
}

func newAPI(ctx context.Context, client string) *api {
	// Keys come from the internal address, while the issuer string checked
	// in the token is the public one: the same split the real APIs already
	// live with for Keycloak.
	keys := oidc.NewRemoteKeySet(ctx, iamURL+"/.well-known/jwks.json")
	return &api{client: client, verifier: oidc.NewVerifier(iamIssuer, keys, &oidc.Config{ClientID: client})}
}

// authenticate is the whole integration: verify the one trusted issuer and
// check the audience. No prefix branching, no second key set.
func (a *api) authenticate(r *http.Request) (caller, int, string) {
	scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if raw == "" || !strings.EqualFold(scheme, "Bearer") {
		return caller{Kind: "anonymous", Roles: []string{}}, 0, ""
	}
	tok, err := a.verifier.Verify(r.Context(), raw)
	if err != nil {
		return caller{}, http.StatusUnauthorized, err.Error()
	}
	var c claims
	if err := tok.Claims(&c); err != nil {
		return caller{}, http.StatusUnauthorized, err.Error()
	}
	roles := append([]string{}, c.ResourceAccess[a.client].Roles...)
	sort.Strings(roles)
	return caller{Kind: c.Principal, Subject: c.Subject, Username: c.Username, TokenID: c.TokenID, Roles: roles, claims: c}, 0, ""
}

func (a *api) handle(requireAuth bool, next func(http.ResponseWriter, *http.Request, caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, status, message := a.authenticate(r)
		if status == 0 && requireAuth && c.Kind == "anonymous" {
			status, message = http.StatusUnauthorized, "Send Authorization: Bearer <token>."
		}
		if status != 0 {
			writeJSON(w, status, map[string]string{"error": "invalid_token", "message": message})
			return
		}
		next(w, r, c)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func forbidden(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden", "message": message})
}

// --- timeseries: role name -> dataset filter, quota tier from ODH_ROLE_* ---

var datasets = []struct{ Name, Role string }{
	{"parking-open", ""},
	{"traffic-a22", "A22"},
	{"bluetooth-blc", "BLC"},
	{"sensors-cbz", "CBZ"},
}

func timeseriesDatasets(w http.ResponseWriter, _ *http.Request, c caller) {
	admin := slices.Contains(c.Roles, "BDP_ADMIN")
	visible := []string{}
	for _, d := range datasets {
		if d.Role == "" || admin || slices.Contains(c.Roles, "BDP_"+d.Role) {
			visible = append(visible, d.Name)
		}
	}
	quota := "GUEST"
	if c.Kind != "anonymous" {
		quota = "BASIC"
		for _, tier := range []string{"ADVANCED", "PREMIUM", "ADMIN"} {
			if slices.Contains(c.Roles, "ODH_ROLE_"+tier) {
				quota = tier
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"caller": c, "quota": quota, "datasets": visible})
}

type preferencesEntry struct {
	data    json.RawMessage
	expires time.Time
}

var preferencesCache = struct {
	sync.Mutex
	entries map[string]preferencesEntry
}{entries: make(map[string]preferencesEntry)}

var dataClient = &http.Client{Timeout: 5 * time.Second}

// timeseriesMe shows a resource server reading user data on demand with its service key.
func timeseriesMe(w http.ResponseWriter, r *http.Request, c caller) {
	preferencesCache.Lock()
	entry, found := preferencesCache.entries[c.Subject]
	preferencesCache.Unlock()
	if !found || !time.Now().Before(entry.expires) {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, iamURL+"/v1/users/"+url.PathEscape(c.Subject)+"/data/preferences", nil)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "data_unavailable"})
			return
		}
		req.Header.Set("Authorization", "Bearer "+os.Getenv("DEMO_SERVICE_KEY"))
		res, err := dataClient.Do(req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "data_unavailable"})
			return
		}
		defer res.Body.Close()
		entry = preferencesEntry{expires: time.Now().Add(10 * time.Second)}
		switch res.StatusCode {
		case http.StatusOK:
			err = json.NewDecoder(res.Body).Decode(&entry.data)
		case http.StatusNotFound:
		default:
			err = fmt.Errorf("user data: status %d", res.StatusCode)
		}
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "data_unavailable"})
			return
		}
		preferencesCache.Lock()
		preferencesCache.entries[c.Subject] = entry
		preferencesCache.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]any{"caller": c, "preferences": entry.data})
}

// --- content: UMA permission list, "Type?condition" resources ---

func contentPermissions(c caller) []permission {
	perms := c.claims.Permissions["odh-tourism-api"]
	if perms == nil {
		perms = []permission{}
	}
	return perms
}

func contentListPermissions(w http.ResponseWriter, _ *http.Request, c caller) {
	writeJSON(w, http.StatusOK, map[string]any{"caller": c, "permissions": contentPermissions(c)})
}

func contentRead(w http.ResponseWriter, r *http.Request, c caller) {
	entity := r.PathValue("type")
	access := []string{"ANONYMOUS"}
	for _, p := range contentPermissions(c) {
		name, cond, _ := strings.Cut(p.RsName, "?")
		if role, ok := strings.CutPrefix(cond, "accessrole="); ok && name == entity && slices.Contains(p.Scopes, "Read") {
			access = append(access, role)
		}
	}
	sort.Strings(access)
	writeJSON(w, http.StatusOK, map[string]any{"caller": c, "type": entity, "accessRoles": access})
}

func contentCreate(w http.ResponseWriter, r *http.Request, c caller) {
	entity, source := r.PathValue("type"), r.URL.Query().Get("source")
	for _, p := range contentPermissions(c) {
		if !slices.Contains(p.Scopes, "Create") {
			continue
		}
		name, cond, _ := strings.Cut(p.RsName, "?")
		if name != entity {
			continue
		}
		if cond == "" || slices.Contains(strings.Split(cond, "&"), "source="+source) {
			writeJSON(w, http.StatusCreated, map[string]any{"caller": c, "created": entity, "source": source, "grantedBy": p.RsName})
			return
		}
	}
	forbidden(w, "No Create permission on "+entity+" for source "+source+".")
}

// --- parking: capability role plus origin:<name> scope roles ---

func parkingScope(w http.ResponseWriter, _ *http.Request, c caller) {
	role := ""
	switch {
	case slices.Contains(c.Roles, "admin"):
		role = "admin"
	case slices.Contains(c.Roles, "operator"):
		role = "operator"
	default:
		forbidden(w, "no parking role")
		return
	}
	origins := []string{}
	for _, r := range c.Roles {
		if origin, ok := strings.CutPrefix(r, "origin:"); ok {
			origins = append(origins, origin)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"caller": c, "role": role, "origins": origins})
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	ctx := context.Background()
	timeseries := newAPI(ctx, "odh-mobility-v2")
	content := newAPI(ctx, "odh-api-core")
	parking := newAPI(ctx, "opendatahub-parking-control-tower")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /timeseries/datasets", timeseries.handle(false, timeseriesDatasets))
	mux.HandleFunc("GET /timeseries/me", timeseries.handle(true, timeseriesMe))
	mux.HandleFunc("GET /content/permissions", content.handle(true, contentListPermissions))
	mux.HandleFunc("GET /content/{type}", content.handle(false, contentRead))
	mux.HandleFunc("POST /content/{type}", content.handle(true, contentCreate))
	mux.HandleFunc("GET /parking/scope", parking.handle(true, parkingScope))

	addr := env("DEMO_LISTEN", ":4011")
	slog.Info("demo api listening", "addr", addr, "issuer", iamIssuer)
	if err := http.ListenAndServe(addr, cors(mux)); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}
