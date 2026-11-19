package issuer

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotationKeepsOldTokensVerifiable(t *testing.T) {
	dir := t.TempDir()
	first, err := New("https://iam.test", dir)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.pem"))
	if len(files) != 1 {
		t.Fatalf("first start must create one key, found %v", files)
	}
	raw, err := first.Sign("u1", []string{"api"}, time.Minute, map[string]any{"odh_principal": "session"})
	if err != nil {
		t.Fatal(err)
	}

	// A file sorting after the generated one becomes the signing key.
	if err := createKey(filepath.Join(dir, "9999-next.pem")); err != nil {
		t.Fatal(err)
	}
	rotated, err := New("https://iam.test", dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(rotated.JWKS().Keys); n != 2 {
		t.Fatalf("%d keys published, want both", n)
	}
	if rotated.JWKS().Keys[0].KeyID == first.JWKS().Keys[0].KeyID {
		t.Fatal("the newer file must sign")
	}
	var extra struct {
		Kind string `json:"odh_principal"`
	}
	claims, err := rotated.Verify(raw, &extra)
	if err != nil {
		t.Fatalf("a token of the previous key must verify: %v", err)
	}
	if claims.Subject != "u1" || extra.Kind != "session" {
		t.Fatalf("claims %+v %+v", claims, extra)
	}
	fresh, _ := rotated.Sign("u2", []string{"api"}, time.Minute, nil)
	if _, err := rotated.Verify(fresh, nil); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	after, err := New("https://iam.test", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := after.Verify(raw, &extra); err == nil {
		t.Fatal("once the old file is removed its tokens must fail")
	}
}

func TestDuplicateKeysAreRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := New("https://iam.test", dir); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.pem"))
	raw, _ := os.ReadFile(files[0])
	if err := os.WriteFile(filepath.Join(dir, "copy.pem"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New("https://iam.test", dir); err == nil {
		t.Fatal("the same key under two names must be refused")
	}
}

func TestIsOwnAndExpiry(t *testing.T) {
	iss, err := New("https://iam.test", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := iss.Sign("u1", []string{"api"}, -time.Second, nil)
	if !iss.IsOwn(raw) {
		t.Fatal("IsOwn looks at the issuer only")
	}
	if _, err := iss.Verify(raw, nil); err == nil {
		t.Fatal("an expired token must not verify")
	}
	if iss.IsOwn("not.a.jwt") {
		t.Fatal("garbage is not ours")
	}
}
