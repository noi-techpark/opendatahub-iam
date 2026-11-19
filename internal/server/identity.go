package server

import (
	"context"
	"sync"
	"time"

	"github.com/noi-techpark/opendatahub-iam/internal/grants"
	"github.com/noi-techpark/opendatahub-iam/internal/keycloak"
	"github.com/noi-techpark/opendatahub-iam/internal/uma"
)

// identity is what Keycloak says about a user right now.
type identity struct {
	User  keycloak.User
	Roles grants.Roles
}

type cached[T any] struct {
	value T
	at    time.Time
}

// directory fronts Keycloak with a short cache. Its TTL, added to the cache
// resource servers keep, bounds how long a role change or a disabled account
// takes to reach an API token.
type directory struct {
	admin     *keycloak.Admin
	clients   []string
	ttl       time.Duration
	policyTTL time.Duration

	mu     sync.Mutex
	users  map[string]cached[identity]
	policy map[string]cached[*uma.Evaluator]

	// Reading a UMA configuration takes a few hundred Keycloak calls; one
	// reload at a time.
	policyLoad sync.Mutex
}

func newDirectory(admin *keycloak.Admin, clients []string, ttl, policyTTL time.Duration) *directory {
	return &directory{
		admin:     admin,
		clients:   clients,
		ttl:       ttl,
		policyTTL: policyTTL,
		users:     map[string]cached[identity]{},
		policy:    map[string]cached[*uma.Evaluator]{},
	}
}

func (d *directory) identity(ctx context.Context, userID string, fresh bool) (identity, error) {
	d.mu.Lock()
	hit, ok := d.users[userID]
	d.mu.Unlock()
	if ok && !fresh && time.Since(hit.at) < d.ttl {
		return hit.value, nil
	}

	user, err := d.admin.User(ctx, userID)
	if err != nil {
		return identity{}, err
	}
	id := identity{User: user, Roles: grants.Roles{}}
	if user.Enabled {
		for _, client := range d.clients {
			roles, err := d.admin.EffectiveClientRoles(ctx, userID, client)
			if err != nil {
				return identity{}, err
			}
			if len(roles) > 0 {
				id.Roles[client] = roles
			}
		}
	}

	d.mu.Lock()
	if len(d.users) > 50_000 {
		for k, v := range d.users {
			if time.Since(v.at) >= d.ttl {
				delete(d.users, k)
			}
		}
	}
	d.users[userID] = cached[identity]{id, time.Now()}
	d.mu.Unlock()
	return id, nil
}

func (d *directory) evaluator(ctx context.Context, clientID string) (*uma.Evaluator, error) {
	fresh := func() (*uma.Evaluator, bool) {
		d.mu.Lock()
		defer d.mu.Unlock()
		hit, ok := d.policy[clientID]
		return hit.value, ok && time.Since(hit.at) < d.policyTTL
	}
	if e, ok := fresh(); ok {
		return e, nil
	}
	d.policyLoad.Lock()
	defer d.policyLoad.Unlock()
	if e, ok := fresh(); ok {
		return e, nil
	}
	raw, err := d.admin.AuthzSettings(ctx, clientID)
	if err != nil {
		return nil, err
	}
	e, err := uma.Load(raw)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.policy[clientID] = cached[*uma.Evaluator]{e, time.Now()}
	d.mu.Unlock()
	return e, nil
}
