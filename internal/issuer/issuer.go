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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type Issuer struct {
	URL    string
	signer jose.Signer
	// Every key in the directory, the signing one first; the others verify
	// JWTs signed before a rotation until they expire.
	jwks jose.JSONWebKeySet
}

// New loads every *.pem key in dir and publishes them all; the key whose file
// name sorts last signs. Name keys so that a newer one sorts later (an ISO
// date does). An empty or missing directory gets a generated key on first
// start. Whoever holds the signing key can assert any identity to every
// resource server.
//
// Rotation: add the new key file, deploy; once the longest JWT lifetime has
// passed, remove the old file and deploy again. Tokens signed before the
// switch verify throughout.
func New(publicURL, dir string) (*Issuer, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if len(files) == 0 {
		file := filepath.Join(dir, time.Now().UTC().Format("2006-01-02T150405Z")+".pem")
		if err := createKey(file); err != nil {
			return nil, err
		}
		files = []string{file}
	}

	var jwks jose.JSONWebKeySet
	var active *rsa.PrivateKey
	seen := map[string]string{}
	for _, file := range files {
		key, err := loadKey(file)
		if err != nil {
			return nil, err
		}
		if other, dup := seen[keyID(key)]; dup {
			return nil, fmt.Errorf("%s and %s hold the same key", other, file)
		}
		seen[keyID(key)] = file
		jwks.Keys = append(jwks.Keys, publicKey(key))
		active = key
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: active, KeyID: keyID(active)}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}
	// The signing key first, so a reader that ignores kid still gets it.
	slices.Reverse(jwks.Keys)
	return &Issuer{URL: publicURL, signer: signer, jwks: jwks}, nil
}

func keyID(key *rsa.PrivateKey) string {
	sum := sha256.Sum256(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

func publicKey(key *rsa.PrivateKey) jose.JSONWebKey {
	return jose.JSONWebKey{Key: &key.PublicKey, KeyID: keyID(key), Algorithm: string(jose.RS256), Use: "sig"}
}

func createKey(file string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return os.WriteFile(file, pem.EncodeToMemory(block), 0o600)
}

func loadKey(file string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return parseKey(file, raw)
}

func parseKey(file string, raw []byte) (*rsa.PrivateKey, error) {
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

// Verify checks a JWT this service signed with any published key.
func (i *Issuer) Verify(raw string, extra any) (jwt.Claims, error) {
	var claims jwt.Claims
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return claims, err
	}
	if len(tok.Headers) != 1 {
		return claims, fmt.Errorf("expected one signature")
	}
	keys := i.jwks.Key(tok.Headers[0].KeyID)
	if len(keys) != 1 {
		return claims, fmt.Errorf("unknown signing key")
	}
	dests := []any{&claims}
	if extra != nil {
		dests = append(dests, extra)
	}
	if err = tok.Claims(keys[0].Key, dests...); err != nil {
		return claims, err
	}
	if claims.Expiry == nil || !time.Now().Before(claims.Expiry.Time()) {
		return claims, fmt.Errorf("expired or missing expiry")
	}
	return claims, claims.ValidateWithLeeway(jwt.Expected{Issuer: i.URL, Time: time.Now()}, 0)
}
