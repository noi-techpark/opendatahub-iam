package uma

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The fixture is the real odh-tourism-api configuration carried by the dev realm.
func tourismSettings(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../keycloak/realm-noi-dev.json")
	if err != nil {
		t.Fatal(err)
	}
	var realm struct {
		Clients []struct {
			ClientID string         `json:"clientId"`
			Authz    map[string]any `json:"authorizationSettings"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(raw, &realm); err != nil {
		t.Fatal(err)
	}
	for _, c := range realm.Clients {
		if c.ClientID == "odh-tourism-api" {
			return c.Authz
		}
	}
	t.Fatal("odh-tourism-api not in fixture")
	return nil
}

func load(t *testing.T, settings map[string]any) (*Evaluator, error) {
	t.Helper()
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	return Load(raw)
}

func holding(roles ...string) func(string) bool {
	return func(id string) bool {
		for _, r := range roles {
			if id == "odh-api-core/"+r {
				return true
			}
		}
		return false
	}
}

func byName(perms []Permission) map[string][]string {
	out := map[string][]string{}
	for _, p := range perms {
		out[p.RsName] = p.Scopes
	}
	return out
}

func TestTourismConfiguration(t *testing.T) {
	e, err := load(t, tourismSettings(t))
	if err != nil {
		t.Fatalf("real configuration must load: %v", err)
	}

	t.Run("no roles, no permissions", func(t *testing.T) {
		if got := e.Permissions(holding()); len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("scope permission grants only its scopes", func(t *testing.T) {
		got := byName(e.Permissions(holding("ArticleNOIManager")))
		want := map[string][]string{"Article?source=noi": {"Create", "Delete", "Update"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v want %v", got, want)
		}
	})

	t.Run("one policy feeds several permissions", func(t *testing.T) {
		got := byName(e.Permissions(holding("EventNOIManager")))
		want := map[string][]string{
			"Event?source=noi": {"Create", "Delete", "Update"},
			"Venue?source=noi": {"Create", "Update"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v want %v", got, want)
		}
	})

	t.Run("resource permission grants every scope of the resource", func(t *testing.T) {
		got := byName(e.Permissions(holding("DataWriter")))
		if len(got) != 32 {
			t.Fatalf("DataWriter covers %d resources, want 32", len(got))
		}
		if want := []string{"Create", "Delete", "Read", "Update"}; !reflect.DeepEqual(got["Article"], want) {
			t.Fatalf("Article: got %v want %v", got["Article"], want)
		}
	})

	t.Run("any listed role satisfies a non-required role policy", func(t *testing.T) {
		got := byName(e.Permissions(holding("MetaDataUpdate")))
		want := map[string][]string{"MetaData": {"Create", "Delete", "Update"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v want %v", got, want)
		}
	})

	t.Run("permissions of several roles are unioned", func(t *testing.T) {
		got := byName(e.Permissions(holding("IDM", "A22")))
		if want := []string{"Read"}; !reflect.DeepEqual(got["WebcamInfo?accessrole=IDM"], want) ||
			!reflect.DeepEqual(got["WebcamInfo?accessrole=A22"], want) {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("roles of another client do not match", func(t *testing.T) {
		got := e.Permissions(func(id string) bool { return id == "odh-mobility-v2/DataWriter" || id == "DataWriter" })
		if len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})
}

func TestRequiredRole(t *testing.T) {
	settings := map[string]any{
		"policyEnforcementMode": "ENFORCING",
		"decisionStrategy":      "AFFIRMATIVE",
		"resources":             []any{map[string]any{"name": "Thing", "scopes": []any{map[string]any{"name": "Read"}}}},
		"policies": []any{
			map[string]any{"name": "both", "type": "role", "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS",
				"config": map[string]any{"roles": `[{"id":"c/a","required":true},{"id":"c/b","required":false}]`}},
			map[string]any{"name": "read thing", "type": "resource", "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS",
				"config": map[string]any{"resources": `["Thing"]`, "applyPolicies": `["both"]`}},
		},
	}
	e, err := load(t, settings)
	if err != nil {
		t.Fatal(err)
	}
	has := func(roles ...string) func(string) bool {
		return func(id string) bool {
			for _, r := range roles {
				if r == id {
					return true
				}
			}
			return false
		}
	}
	if got := e.Permissions(has("c/b")); len(got) != 0 {
		t.Fatalf("optional role without the required one must not grant: %v", got)
	}
	if got := e.Permissions(has("c/a")); len(got) != 1 {
		t.Fatalf("required role alone must grant: %v", got)
	}
}

// Anything the evaluator does not reproduce must be refused at load time.
func TestLoadRefusesUnsupportedConfiguration(t *testing.T) {
	policy := func(overrides map[string]any) map[string]any {
		p := map[string]any{"name": "p", "type": "role", "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS",
			"config": map[string]any{"roles": `[{"id":"c/a","required":false}]`}}
		for k, v := range overrides {
			p[k] = v
		}
		return p
	}
	permission := func(config map[string]any) map[string]any {
		return map[string]any{"name": "perm", "type": "resource", "logic": "POSITIVE", "decisionStrategy": "UNANIMOUS", "config": config}
	}
	base := func(mutate func(map[string]any)) map[string]any {
		s := map[string]any{
			"policyEnforcementMode": "ENFORCING",
			"decisionStrategy":      "AFFIRMATIVE",
			"resources":             []any{map[string]any{"name": "Thing", "scopes": []any{}}},
			"policies": []any{policy(nil),
				permission(map[string]any{"resources": `["Thing"]`, "applyPolicies": `["p"]`})},
		}
		mutate(s)
		return s
	}

	cases := map[string]struct {
		settings map[string]any
		wantErr  string
	}{
		"permissive enforcement":    {base(func(s map[string]any) { s["policyEnforcementMode"] = "PERMISSIVE" }), "enforcement mode"},
		"unanimous resource server": {base(func(s map[string]any) { s["decisionStrategy"] = "UNANIMOUS" }), "decision strategy"},
		"negative logic": {base(func(s map[string]any) {
			s["policies"].([]any)[0] = policy(map[string]any{"logic": "NEGATIVE"})
		}), "logic"},
		"script policy": {base(func(s map[string]any) {
			s["policies"] = append(s["policies"].([]any), map[string]any{"name": "js", "type": "js", "logic": "POSITIVE", "config": map[string]any{}})
		}), "type"},
		"permission applying a non-role policy": {base(func(s map[string]any) {
			s["policies"].([]any)[1] = permission(map[string]any{"resources": `["Thing"]`, "applyPolicies": `["missing"]`})
		}), "not a role policy"},
		"resource type permission": {base(func(s map[string]any) {
			s["policies"].([]any)[1] = permission(map[string]any{"defaultResourceType": "urn:x", "applyPolicies": `["p"]`})
		}), "defaultResourceType"},
		"consensus permission": {base(func(s map[string]any) {
			p := permission(map[string]any{"resources": `["Thing"]`, "applyPolicies": `["p"]`})
			p["decisionStrategy"] = "CONSENSUS"
			s["policies"].([]any)[1] = p
		}), "decision strategy"},
		"user managed resource": {base(func(s map[string]any) {
			s["resources"] = []any{map[string]any{"name": "Thing", "ownerManagedAccess": true}}
		}), "user-managed"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, tc.settings)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got error %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}

	if _, err := load(t, base(func(map[string]any) {})); err != nil {
		t.Fatalf("the unmodified base must load: %v", err)
	}
}
