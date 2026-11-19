package token

import (
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	id, full, hash := New()
	gotID, secret, ok := Parse(full)
	if !ok || gotID != id {
		t.Fatalf("Parse(%q) = %q, %v", full, gotID, ok)
	}
	if !Matches(secret, hash) {
		t.Fatal("secret does not match its own hash")
	}
	if Matches(strings.Repeat("0", 64), hash) {
		t.Fatal("a different secret matched")
	}
	if strings.Contains(string(hash), secret) {
		t.Fatal("hash contains the secret")
	}

	_, other, _ := New()
	if other == full {
		t.Fatal("two tokens are identical")
	}
}

func TestParseRejects(t *testing.T) {
	_, valid, _ := New()
	for name, s := range map[string]string{
		"empty":           "",
		"jwt":             "eyJhbGciOiJSUzI1NiJ9.e30.sig",
		"prefix only":     Prefix,
		"truncated":       valid[:len(valid)-1],
		"extended":        valid + "0",
		"upper case":      strings.ToUpper(valid),
		"wrong separator": valid[:len(Prefix)+16] + "-" + valid[len(Prefix)+17:],
		"non hex":         valid[:len(valid)-1] + "g",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := Parse(s); ok {
				t.Fatalf("Parse(%q) accepted", s)
			}
		})
	}
}
