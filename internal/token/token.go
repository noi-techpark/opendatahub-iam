// Package token defines the opaque API token format:
//
//	odh_pat_<16 hex id>_<64 hex secret>
//
// The id is the lookup key; only a SHA-256 of the secret is stored. The secret
// carries 256 bits of entropy, so a fast hash is sufficient.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

const (
	Prefix    = "odh_pat_"
	idLen     = 16
	secretLen = 64
)

func Looks(s string) bool { return strings.HasPrefix(s, Prefix) }

func New() (id, full string, hash []byte) {
	buf := make([]byte, (idLen+secretLen)/2)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	id = hex.EncodeToString(buf[:idLen/2])
	secret := hex.EncodeToString(buf[idLen/2:])
	return id, Prefix + id + "_" + secret, Hash(secret)
}

func Parse(s string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(s, Prefix)
	if !found || len(rest) != idLen+1+secretLen || rest[idLen] != '_' {
		return "", "", false
	}
	id, secret = rest[:idLen], rest[idLen+1:]
	if !isHex(id) || !isHex(secret) {
		return "", "", false
	}
	return id, secret, true
}

func Hash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func Matches(secret string, hash []byte) bool {
	return subtle.ConstantTimeCompare(Hash(secret), hash) == 1
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
