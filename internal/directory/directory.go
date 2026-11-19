// Package directory is what Keycloak says about a user right now, read
// through a short cache. The cache TTL, added to the cache a resource server
// keeps, bounds how long a role change or a disabled account takes to reach
// an API token.
package directory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/noi-techpark/opendatahub-go-sdk/tel/logger"

	"github.com/noi-techpark/opendatahub-iam/internal/cache"
	"github.com/noi-techpark/opendatahub-iam/internal/grants"
	"github.com/noi-techpark/opendatahub-iam/internal/keycloak"
	"github.com/noi-techpark/opendatahub-iam/internal/uma"
)

// Source is the read-only slice of the Keycloak admin API the directory needs.
type Source interface {
	User(ctx context.Context, id string) (keycloak.User, error)
	UserByUsername(ctx context.Context, username string) (keycloak.User, error)
	EffectiveClientRoles(ctx context.Context, userID, clientID string) ([]string, error)
	AuthzSettings(ctx context.Context, clientID string) ([]byte, error)
}

// Identity is a user and the roles they hold on the API clients.
type Identity struct {
	User  keycloak.User
	Roles grants.Roles
}

type Directory struct {
	source    Source
	clients   []string
	ttl       time.Duration
	policyTTL time.Duration

	users    cache.Cache[Identity]
	policies cache.Cache[*uma.Evaluator]

	// Reading a UMA configuration takes a few hundred Keycloak calls; one
	// reload at a time.
	policyLoad sync.Mutex
}

// New reads users through source for the given API clients. The users cache
// may be shared between replicas; the policy cache holds parsed evaluators
// and stays local.
func New(source Source, clients []string, ttl, policyTTL time.Duration,
	users cache.Cache[Identity], policies cache.Cache[*uma.Evaluator]) *Directory {
	return &Directory{source: source, clients: clients, ttl: ttl, policyTTL: policyTTL, users: users, policies: policies}
}

// Identity returns the user and their roles, from the cache unless it has
// expired or fresh is set. A failing cache is bypassed, not fatal.
func (d *Directory) Identity(ctx context.Context, userID string, fresh bool) (Identity, error) {
	if !fresh {
		if id, ok := d.cached(ctx, userID); ok {
			return id, nil
		}
	}
	user, err := d.source.User(ctx, userID)
	if err != nil {
		return Identity{}, err
	}
	id := Identity{User: user, Roles: grants.Roles{}}
	if user.Enabled {
		for _, client := range d.clients {
			roles, err := d.source.EffectiveClientRoles(ctx, userID, client)
			if err != nil {
				return Identity{}, err
			}
			if len(roles) > 0 {
				id.Roles[client] = roles
			}
		}
	}
	if err := d.users.Set(ctx, userID, id, d.ttl); err != nil {
		logger.Get(ctx).Warn("user cache write failed", "err", err)
	}
	return id, nil
}

// Lookup accepts a Keycloak id or a username, for operators who know a
// person by name. Usernames are resolved by Keycloak, never from a copy.
func (d *Directory) Lookup(ctx context.Context, ref string) (Identity, error) {
	id, err := d.Identity(ctx, ref, false)
	if !errors.Is(err, keycloak.ErrNotFound) {
		return id, err
	}
	user, err := d.source.UserByUsername(ctx, ref)
	if err != nil {
		return Identity{}, err
	}
	return d.Identity(ctx, user.ID, false)
}

func (d *Directory) cached(ctx context.Context, userID string) (Identity, bool) {
	id, ok, err := d.users.Get(ctx, userID)
	if err != nil {
		logger.Get(ctx).Warn("user cache read failed", "err", err)
		return Identity{}, false
	}
	return id, ok
}

// Evaluator returns the parsed UMA configuration of a client.
func (d *Directory) Evaluator(ctx context.Context, clientID string) (*uma.Evaluator, error) {
	if e, ok, _ := d.policies.Get(ctx, clientID); ok {
		return e, nil
	}
	d.policyLoad.Lock()
	defer d.policyLoad.Unlock()
	if e, ok, _ := d.policies.Get(ctx, clientID); ok {
		return e, nil
	}
	raw, err := d.source.AuthzSettings(ctx, clientID)
	if err != nil {
		return nil, err
	}
	e, err := uma.Load(raw)
	if err != nil {
		return nil, err
	}
	if err := d.policies.Set(ctx, clientID, e, d.policyTTL); err != nil {
		logger.Get(ctx).Warn("policy cache write failed", "err", err)
	}
	return e, nil
}
