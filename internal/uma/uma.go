// Package uma evaluates a Keycloak authorization configuration for a set of
// roles, without a user access token.
//
// Keycloak can only evaluate UMA permissions against a live access token,
// which an API token does not have. This package reproduces the subset of the
// evaluator that role-based configurations use. Load rejects anything outside
// that subset, so an unsupported policy fails loudly rather than being
// evaluated wrongly.
package uma

import (
	"encoding/json"
	"fmt"
	"sort"
)

type Permission struct {
	RsName string   `json:"rsname"`
	Scopes []string `json:"scopes,omitempty"`
}

type settings struct {
	PolicyEnforcementMode string `json:"policyEnforcementMode"`
	DecisionStrategy      string `json:"decisionStrategy"`
	Resources             []struct {
		Name               string `json:"name"`
		OwnerManagedAccess bool   `json:"ownerManagedAccess"`
		Scopes             []struct {
			Name string `json:"name"`
		} `json:"scopes"`
	} `json:"resources"`
	Policies []struct {
		Name             string            `json:"name"`
		Type             string            `json:"type"`
		Logic            string            `json:"logic"`
		DecisionStrategy string            `json:"decisionStrategy"`
		Config           map[string]string `json:"config"`
	} `json:"policies"`
}

type roleRef struct {
	ID       string `json:"id"`
	Required bool   `json:"required"`
}

type permission struct {
	name      string
	policies  [][]roleRef
	unanimous bool
	resources []string
	// nil means every scope of each resource (a resource-based permission).
	scopes []string
}

type Evaluator struct {
	order          []string
	resourceScopes map[string][]string
	permissions    []permission
}

// Load parses the document returned by Keycloak's
// /clients/{id}/authz/resource-server/settings endpoint.
func Load(raw []byte) (*Evaluator, error) {
	var s settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.PolicyEnforcementMode != "ENFORCING" {
		return nil, fmt.Errorf("unsupported policy enforcement mode %q", s.PolicyEnforcementMode)
	}
	if s.DecisionStrategy != "AFFIRMATIVE" {
		return nil, fmt.Errorf("unsupported resource server decision strategy %q", s.DecisionStrategy)
	}

	e := &Evaluator{resourceScopes: map[string][]string{}}
	for _, r := range s.Resources {
		if r.OwnerManagedAccess {
			return nil, fmt.Errorf("resource %q: user-managed access is not supported", r.Name)
		}
		scopes := make([]string, len(r.Scopes))
		for i, sc := range r.Scopes {
			scopes[i] = sc.Name
		}
		e.order = append(e.order, r.Name)
		e.resourceScopes[r.Name] = scopes
	}
	sort.Strings(e.order)

	rolePolicies := map[string][]roleRef{}
	for _, p := range s.Policies {
		if p.Logic != "POSITIVE" {
			return nil, fmt.Errorf("policy %q: logic %q is not supported", p.Name, p.Logic)
		}
		if p.Type != "role" {
			continue
		}
		var refs []roleRef
		if err := json.Unmarshal([]byte(p.Config["roles"]), &refs); err != nil || len(refs) == 0 {
			return nil, fmt.Errorf("policy %q: unreadable role list", p.Name)
		}
		rolePolicies[p.Name] = refs
	}

	for _, p := range s.Policies {
		switch p.Type {
		case "role":
			continue
		case "scope", "resource":
		default:
			return nil, fmt.Errorf("policy %q: type %q is not supported", p.Name, p.Type)
		}
		perm := permission{name: p.Name}
		switch p.DecisionStrategy {
		case "UNANIMOUS":
			perm.unanimous = true
		case "AFFIRMATIVE":
		default:
			return nil, fmt.Errorf("permission %q: decision strategy %q is not supported", p.Name, p.DecisionStrategy)
		}
		for key := range p.Config {
			switch key {
			case "resources", "scopes", "applyPolicies":
			default:
				// e.g. defaultResourceType: a permission on a resource type.
				return nil, fmt.Errorf("permission %q: %q is not supported", p.Name, key)
			}
		}
		if err := list(p.Config["resources"], &perm.resources); err != nil || len(perm.resources) == 0 {
			return nil, fmt.Errorf("permission %q: must name its resources explicitly", p.Name)
		}
		for _, r := range perm.resources {
			if _, ok := e.resourceScopes[r]; !ok {
				return nil, fmt.Errorf("permission %q: unknown resource %q", p.Name, r)
			}
		}
		if p.Type == "scope" {
			if err := list(p.Config["scopes"], &perm.scopes); err != nil || len(perm.scopes) == 0 {
				return nil, fmt.Errorf("permission %q: scope permission without scopes", p.Name)
			}
		}
		var applied []string
		if err := list(p.Config["applyPolicies"], &applied); err != nil || len(applied) == 0 {
			return nil, fmt.Errorf("permission %q: no policies applied", p.Name)
		}
		for _, name := range applied {
			refs, ok := rolePolicies[name]
			if !ok {
				return nil, fmt.Errorf("permission %q: policy %q is not a role policy", p.Name, name)
			}
			perm.policies = append(perm.policies, refs)
		}
		e.permissions = append(e.permissions, perm)
	}
	return e, nil
}

func list(raw string, into *[]string) error {
	if raw == "" {
		return nil
	}
	return json.Unmarshal([]byte(raw), into)
}

// Permissions returns what Keycloak's response_mode=permissions would for a
// caller holding exactly the given roles. Role ids use Keycloak's export
// form: "client/role" for client roles, bare "role" for realm roles.
func (e *Evaluator) Permissions(has func(roleID string) bool) []Permission {
	granted := map[string]map[string]bool{}
	for _, p := range e.permissions {
		if !p.permits(has) {
			continue
		}
		for _, r := range p.resources {
			if granted[r] == nil {
				granted[r] = map[string]bool{}
			}
			for _, sc := range e.resourceScopes[r] {
				if p.scopes == nil || contains(p.scopes, sc) {
					granted[r][sc] = true
				}
			}
		}
	}
	out := []Permission{}
	for _, r := range e.order {
		scopes, ok := granted[r]
		if !ok {
			continue
		}
		perm := Permission{RsName: r}
		for sc := range scopes {
			perm.Scopes = append(perm.Scopes, sc)
		}
		sort.Strings(perm.Scopes)
		out = append(out, perm)
	}
	return out
}

func (p permission) permits(has func(string) bool) bool {
	for _, refs := range p.policies {
		ok := rolePolicyPermits(refs, has)
		if ok && !p.unanimous {
			return true
		}
		if !ok && p.unanimous {
			return false
		}
	}
	return p.unanimous
}

// Keycloak's RolePolicyProvider: a missing required role denies; otherwise
// holding any listed role grants.
func rolePolicyPermits(refs []roleRef, has func(string) bool) bool {
	any := false
	for _, r := range refs {
		held := has(r.ID)
		if !held && r.Required {
			return false
		}
		any = any || held
	}
	return any
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
