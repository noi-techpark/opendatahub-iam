// Package grants implements the allow-list a user attaches to an API token.
//
// A token never stores permissions. It stores which of the owner's roles it
// may carry; what it carries at any moment is that list intersected with the
// roles the owner holds right now.
package grants

import (
	"fmt"
	"path"
	"slices"
	"sort"
)

// All stands for "every role I hold on this client, including future ones".
const All = "*"

// Grants maps a Keycloak client id to the role names the token may carry.
type Grants map[string][]string

// Roles maps a Keycloak client id to role names actually held.
type Roles map[string][]string

type Rules struct {
	Clients   []string
	Inherited []string
}

func (r Rules) IsInherited(role string) bool {
	for _, pattern := range r.Inherited {
		if ok, _ := path.Match(pattern, role); ok {
			return true
		}
	}
	return false
}

// Normalize checks a requested allow-list against the roles the owner holds
// and returns it in canonical form. Inherited roles are dropped: they are
// always carried, so listing them would only suggest they can be withheld.
func (r Rules) Normalize(requested Grants, held Roles) (Grants, error) {
	out := Grants{}
	for client, roles := range requested {
		if !slices.Contains(r.Clients, client) {
			return nil, fmt.Errorf("%q is not an API a token can be scoped to", client)
		}
		if slices.Contains(roles, All) {
			out[client] = []string{All}
			continue
		}
		var keep []string
		for _, role := range roles {
			if r.IsInherited(role) {
				continue
			}
			if !slices.Contains(held[client], role) {
				return nil, fmt.Errorf("you do not hold role %q on %q", role, client)
			}
			if !slices.Contains(keep, role) {
				keep = append(keep, role)
			}
		}
		if len(keep) > 0 {
			sort.Strings(keep)
			out[client] = keep
		}
	}
	return out, nil
}

// Effective returns the roles a token carries now.
func (r Rules) Effective(g Grants, held Roles) Roles {
	out := Roles{}
	for _, client := range r.Clients {
		allowed := g[client]
		all := slices.Contains(allowed, All)
		var roles []string
		for _, role := range held[client] {
			if all || r.IsInherited(role) || slices.Contains(allowed, role) {
				roles = append(roles, role)
			}
		}
		if len(roles) > 0 {
			sort.Strings(roles)
			out[client] = roles
		}
	}
	return out
}

// Only keeps the listed clients.
func (r Roles) Only(clients []string) Roles {
	out := Roles{}
	for _, c := range clients {
		if roles, ok := r[c]; ok {
			out[c] = roles
		}
	}
	return out
}
