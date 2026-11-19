package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// APIClient is a Keycloak client whose roles may be carried by an API token.
// Roles on any other client (realm-management, account, ...) never are.
type APIClient struct {
	ClientID string `json:"clientId"`
	Label    string `json:"label"`
}

type FlatRoleClaim struct {
	Claim  string `json:"claim"`
	Client string `json:"client"`
}

// Service is a resource server allowed to call /v1/resolve.
type Service struct {
	Name     string   `json:"name"`
	KeyEnv   string   `json:"keyEnv"`
	Audience string   `json:"audience"`
	Clients  []string `json:"clients"`
	// Mirrors a Keycloak "User Client Role" mapper for servers that read a flat claim.
	FlatRoleClaim *FlatRoleClaim `json:"flatRoleClaim,omitempty"`
	// Keycloak clients whose UMA permissions this service needs evaluated.
	UMA []string `json:"uma,omitempty"`

	Key string `json:"-"`
}

type Policy struct {
	APIClients []APIClient `json:"apiClients"`
	// Role name globs that every token inherits and that cannot be deselected.
	InheritedRoles []string  `json:"inheritedRoles"`
	Services       []Service `json:"services"`
}

type Config struct {
	Listen      string
	PublicURL   string
	DatabaseURL string

	KeycloakURL          string
	KeycloakRealm        string
	KeycloakIssuer       string
	KeycloakClientID     string
	KeycloakClientSecret string

	SessionAudience string
	// Role on KeycloakClientID that admits a session to the operator routes.
	AdminRole  string
	UIClientID string
	// Directory of *.pem keys; the one sorting last signs, all are published.
	SigningKeysDir string
	DemoAPIURL     string

	CacheTTL       time.Duration
	PolicyTTL      time.Duration
	JWTTTL         time.Duration
	ClientTokenTTL time.Duration

	// Requests per minute one client address may send to the token endpoint
	// and the self-service routes; 0 disables the limit.
	RateLimitPerMinute int
	DBMaxConns         int
	DBStatementTimeout time.Duration

	Policy
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func integer(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func duration(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func Load() (Config, error) {
	c := Config{
		Listen:               env("IAM_LISTEN", ":4010"),
		PublicURL:            strings.TrimRight(env("IAM_PUBLIC_URL", "http://localhost:4010"), "/"),
		DatabaseURL:          os.Getenv("IAM_DATABASE_URL"),
		KeycloakURL:          strings.TrimRight(env("IAM_KEYCLOAK_URL", "http://localhost:8180"), "/"),
		KeycloakRealm:        env("IAM_KEYCLOAK_REALM", "noi"),
		KeycloakClientID:     env("IAM_KEYCLOAK_CLIENT_ID", "odh-iam"),
		KeycloakClientSecret: os.Getenv("IAM_KEYCLOAK_CLIENT_SECRET"),
		SessionAudience:      env("IAM_SESSION_AUDIENCE", "odh-iam"),
		AdminRole:            env("IAM_ADMIN_ROLE", "iam-admin"),
		UIClientID:           env("IAM_UI_CLIENT_ID", "odh-iam-ui"),
		SigningKeysDir:       env("IAM_SIGNING_KEYS_DIR", "data/keys"),
		DemoAPIURL:           strings.TrimRight(os.Getenv("IAM_DEMO_API_URL"), "/"),
	}
	c.KeycloakIssuer = strings.TrimRight(
		env("IAM_KEYCLOAK_ISSUER", c.KeycloakURL+"/realms/"+c.KeycloakRealm), "/")

	var err error
	if c.CacheTTL, err = duration("IAM_CACHE_TTL", 15*time.Second); err != nil {
		return c, err
	}
	if c.PolicyTTL, err = duration("IAM_POLICY_TTL", 60*time.Second); err != nil {
		return c, err
	}
	if c.JWTTTL, err = duration("IAM_JWT_TTL", 60*time.Second); err != nil {
		return c, err
	}
	if c.ClientTokenTTL, err = duration("IAM_CLIENT_TOKEN_TTL", 5*time.Minute); err != nil {
		return c, err
	}
	if c.RateLimitPerMinute, err = integer("IAM_RATE_LIMIT_PER_MINUTE", 300); err != nil {
		return c, err
	}
	if c.DBMaxConns, err = integer("IAM_DB_MAX_CONNS", 10); err != nil {
		return c, err
	}
	if c.DBStatementTimeout, err = duration("IAM_DB_STATEMENT_TIMEOUT", 5*time.Second); err != nil {
		return c, err
	}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("IAM_DATABASE_URL is required")
	}
	if c.KeycloakClientSecret == "" {
		return c, fmt.Errorf("IAM_KEYCLOAK_CLIENT_SECRET is required")
	}

	raw, err := os.ReadFile(env("IAM_CONFIG", "config/dev.json"))
	if err != nil {
		return c, fmt.Errorf("policy config: %w", err)
	}
	if c.Policy, err = ParsePolicy(raw, os.Getenv); err != nil {
		return c, fmt.Errorf("policy config: %w", err)
	}
	return c, nil
}

func ParsePolicy(raw []byte, getenv func(string) string) (Policy, error) {
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if len(p.APIClients) == 0 {
		return p, fmt.Errorf("apiClients is empty")
	}
	known := map[string]bool{}
	for _, a := range p.APIClients {
		if a.ClientID == "" || a.ClientID == "*" {
			return p, fmt.Errorf("invalid api client id %q", a.ClientID)
		}
		known[a.ClientID] = true
	}
	names := map[string]bool{}
	for i := range p.Services {
		s := &p.Services[i]
		if s.Name == "" || names[s.Name] {
			return p, fmt.Errorf("service name %q is empty or duplicated", s.Name)
		}
		names[s.Name] = true
		if s.Audience == "" {
			return p, fmt.Errorf("service %s: audience is required", s.Name)
		}
		for _, c := range s.Clients {
			if !known[c] {
				return p, fmt.Errorf("service %s: client %q is not in apiClients", s.Name, c)
			}
		}
		if f := s.FlatRoleClaim; f != nil && (f.Claim == "" || !known[f.Client]) {
			return p, fmt.Errorf("service %s: invalid flatRoleClaim", s.Name)
		}
		if s.Key = getenv(s.KeyEnv); len(s.Key) < 16 {
			return p, fmt.Errorf("service %s: %s must hold a key of at least 16 characters", s.Name, s.KeyEnv)
		}
	}
	return p, nil
}

func (p Policy) APIClientIDs() []string {
	ids := make([]string, len(p.APIClients))
	for i, a := range p.APIClients {
		ids[i] = a.ClientID
	}
	return ids
}
