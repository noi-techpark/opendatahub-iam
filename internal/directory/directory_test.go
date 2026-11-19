package directory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/noi-techpark/opendatahub-iam/internal/cache"
	"github.com/noi-techpark/opendatahub-iam/internal/keycloak"
	"github.com/noi-techpark/opendatahub-iam/internal/uma"
)

type fakeSource struct {
	users map[string]keycloak.User
	roles map[string][]string // userID/clientID
	calls int
}

func (f *fakeSource) User(_ context.Context, id string) (keycloak.User, error) {
	f.calls++
	u, ok := f.users[id]
	if !ok {
		return keycloak.User{}, keycloak.ErrNotFound
	}
	return u, nil
}

func (f *fakeSource) EffectiveClientRoles(_ context.Context, userID, clientID string) ([]string, error) {
	f.calls++
	return f.roles[userID+"/"+clientID], nil
}

func (f *fakeSource) UserByUsername(_ context.Context, username string) (keycloak.User, error) {
	for _, u := range f.users {
		if u.Username == username {
			return u, nil
		}
	}
	return keycloak.User{}, keycloak.ErrNotFound
}

func (f *fakeSource) AuthzSettings(context.Context, string) ([]byte, error) {
	return nil, errors.New("not in this test")
}

func newTestDirectory(src Source) *Directory {
	return New(src, []string{"api-a", "api-b"}, time.Minute, time.Minute,
		cache.NewMemory[Identity](10), cache.NewMemory[*uma.Evaluator](2))
}

func TestIdentityReadsRolesPerClientAndCaches(t *testing.T) {
	src := &fakeSource{
		users: map[string]keycloak.User{"u1": {ID: "u1", Username: "anna", Enabled: true}},
		roles: map[string][]string{"u1/api-a": {"reader"}},
	}
	d := newTestDirectory(src)
	ctx := context.Background()

	id, err := d.Identity(ctx, "u1", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Roles) != 1 || id.Roles["api-a"][0] != "reader" {
		t.Fatalf("roles %v", id.Roles)
	}
	calls := src.calls
	if _, err := d.Identity(ctx, "u1", false); err != nil || src.calls != calls {
		t.Fatalf("second read hit Keycloak (%d calls)", src.calls-calls)
	}
	if _, err := d.Identity(ctx, "u1", true); err != nil || src.calls == calls {
		t.Fatal("fresh read must hit Keycloak")
	}
}

func TestIdentityOfADisabledUserCarriesNoRoles(t *testing.T) {
	src := &fakeSource{
		users: map[string]keycloak.User{"u1": {ID: "u1", Enabled: false}},
		roles: map[string][]string{"u1/api-a": {"reader"}},
	}
	id, err := newTestDirectory(src).Identity(context.Background(), "u1", false)
	if err != nil || len(id.Roles) != 0 {
		t.Fatalf("%v %v", id.Roles, err)
	}
}

func TestIdentityNotFound(t *testing.T) {
	_, err := newTestDirectory(&fakeSource{users: map[string]keycloak.User{}}).Identity(context.Background(), "ghost", false)
	if !errors.Is(err, keycloak.ErrNotFound) {
		t.Fatalf("err %v", err)
	}
}

func TestLookupAcceptsIDOrUsername(t *testing.T) {
	src := &fakeSource{users: map[string]keycloak.User{"u1": {ID: "u1", Username: "anna", Enabled: true}}}
	d := newTestDirectory(src)
	ctx := context.Background()
	for _, ref := range []string{"u1", "anna"} {
		id, err := d.Lookup(ctx, ref)
		if err != nil || id.User.ID != "u1" {
			t.Fatalf("%s: %+v %v", ref, id.User, err)
		}
	}
	if _, err := d.Lookup(ctx, "ghost"); !errors.Is(err, keycloak.ErrNotFound) {
		t.Fatalf("ghost: %v", err)
	}
}

type brokenCache struct{}

func (brokenCache) Get(context.Context, string) (Identity, bool, error) {
	return Identity{}, false, errors.New("redis down")
}
func (brokenCache) Set(context.Context, string, Identity, time.Duration) error {
	return errors.New("redis down")
}

func TestIdentitySurvivesABrokenCache(t *testing.T) {
	src := &fakeSource{users: map[string]keycloak.User{"u1": {ID: "u1", Enabled: true}}}
	d := New(src, nil, time.Minute, time.Minute, brokenCache{}, cache.NewMemory[*uma.Evaluator](1))
	if _, err := d.Identity(context.Background(), "u1", false); err != nil {
		t.Fatalf("a cache outage must not fail the lookup: %v", err)
	}
}
