// Package issuer signs the short-lived JWTs resource servers receive in
// exchange for an API token, and publishes the matching keys.
package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type Issuer struct {
	URL    string
	signer jose.Signer
	jwks   jose.JSONWebKeySet
}

// New loads the RSA signing key, creating it on first start. Whoever holds
// this key can assert any identity to every resource server.
func New(publicURL, keyFile string) (*Issuer, error) {
	key, err := loadOrCreateKey(keyFile)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	kid := base64.RawURLEncoding.EncodeToString(sum[:12])

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}
	return &Issuer{
		URL:    publicURL,
		signer: signer,
		jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"},
		}},
	}, nil
}

func loadOrCreateKey(file string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			return nil, err
		}
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		return key, os.WriteFile(file, pem.EncodeToMemory(block), 0o600)
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: not a PEM file", file)
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an RSA key", file)
	}
	return key, nil
}

func (i *Issuer) JWKS() jose.JSONWebKeySet { return i.jwks }

// Sign adds the registered claims to extra and returns the compact JWT.
func (i *Issuer) Sign(subject string, audiences []string, ttl time.Duration, extra map[string]any) (string, error) {
	now := time.Now()
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	registered := jwt.Claims{
		Issuer:   i.URL,
		Subject:  subject,
		Audience: jwt.Audience(audiences),
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(ttl)),
		ID:       base64.RawURLEncoding.EncodeToString(id),
	}
	return jwt.Signed(i.signer).Claims(extra).Claims(registered).Serialize()
}

func (i *Issuer) IsOwn(raw string) bool {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return false
	}
	var claims jwt.Claims
	return tok.UnsafeClaimsWithoutVerification(&claims) == nil && claims.Issuer == i.URL
}

func (i *Issuer) Verify(raw string, extra any) (jwt.Claims, error) {
	var claims jwt.Claims
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return claims, err
	}
	if err = tok.Claims(i.jwks.Keys[0].Key, &claims, extra); err != nil {
		return claims, err
	}
	if claims.Expiry == nil || !time.Now().Before(claims.Expiry.Time()) {
		return claims, fmt.Errorf("expired or missing expiry")
	}
	return claims, claims.ValidateWithLeeway(jwt.Expected{Issuer: i.URL, Time: time.Now()}, 0)
}
