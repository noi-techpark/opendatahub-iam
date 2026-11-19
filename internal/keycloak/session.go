package keycloak

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Session is a verified Keycloak access token of an interactive user.
type Session struct {
	Azp            string   `json:"azp"`
	Audience       []string `json:"-"`
	Subject        string   `json:"sub"`
	Username       string   `json:"preferred_username"`
	Email          string   `json:"email"`
	Name           string   `json:"name"`
	Type           string   `json:"typ"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

type Verifier struct {
	strict *oidc.IDTokenVerifier
	any    *oidc.IDTokenVerifier
}

// NewVerifier fetches keys from baseURL but checks the issuer string the
// tokens actually carry; the two differ when Keycloak is reached on an
// internal address.
func NewVerifier(ctx context.Context, baseURL, realm, issuer, audience string) *Verifier {
	keys := oidc.NewRemoteKeySet(ctx,
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", baseURL, realm))
	return &Verifier{
		strict: oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: audience}),
		any:    oidc.NewVerifier(issuer, keys, &oidc.Config{SkipClientIDCheck: true}),
	}
}

// Verify accepts only tokens addressed to this service.
func (v *Verifier) Verify(ctx context.Context, raw string) (Session, error) {
	return verify(ctx, v.strict, raw)
}

// VerifyAnyAudience accepts a token addressed to another resource server,
// which that server forwards when it asks to hydrate a request.
func (v *Verifier) VerifyAnyAudience(ctx context.Context, raw string) (Session, error) {
	return verify(ctx, v.any, raw)
}

func verify(ctx context.Context, verifier *oidc.IDTokenVerifier, raw string) (Session, error) {
	var s Session
	tok, err := verifier.Verify(ctx, raw)
	if err != nil {
		return s, err
	}
	if err := tok.Claims(&s); err != nil {
		return s, err
	}
	s.Audience = tok.Audience
	// Keycloak ID and refresh tokens share the signing key and issuer.
	if s.Type != "Bearer" {
		return s, fmt.Errorf("not an access token (typ %q)", s.Type)
	}
	return s, nil
}
