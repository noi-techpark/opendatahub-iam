//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func roleNames(t *testing.T, session, clientID string) (all, inherited []string) {
	t.Helper()
	var me struct {
		APIs []struct {
			ClientID string `json:"clientId"`
			Roles    []struct {
				Name      string `json:"name"`
				Inherited bool   `json:"inherited"`
			} `json:"roles"`
		} `json:"apis"`
	}
	wantStatus(t, call(t, "GET", iamURL+"/v1/me", session, nil), 200).decode(t, &me)
	for _, api := range me.APIs {
		if api.ClientID != clientID {
			continue
		}
		for _, r := range api.Roles {
			all = append(all, r.Name)
			if r.Inherited {
				inherited = append(inherited, r.Name)
			}
		}
	}
	return all, inherited
}

func TestIdentityShowsCurrentKeycloakRoles(t *testing.T) {
	// Polled: the view is cached briefly and another test may have just
	// restored these roles.
	anna := login(t, "anna")
	eventually(t, "anna's timeseries roles", func() bool {
		all, inherited := roleNames(t, anna, mobility)
		return reflect.DeepEqual(all, []string{"BDP_A22", "BDP_BLC", "ODH_ROLE_PREMIUM"}) &&
			reflect.DeepEqual(inherited, []string{"ODH_ROLE_PREMIUM"})
	})

	// BDP_ADMIN is a composite containing ODH_ROLE_ADMIN.
	walter := login(t, "walter")
	eventually(t, "walter's composite role to be expanded", func() bool {
		all, _ := roleNames(t, walter, mobility)
		return reflect.DeepEqual(all, []string{"BDP_ADMIN", "ODH_ROLE_ADMIN"})
	})

	var raw map[string]any
	wantStatus(t, call(t, "GET", iamURL+"/v1/me", walter, nil), 200).decode(t, &raw)
	if strings.Contains(string(mustJSON(t, raw)), "view-users") {
		t.Fatal("a realm-management role leaked into the identity view")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSelfServiceNeedsAnInteractiveSession(t *testing.T) {
	anna := login(t, "anna")
	tok := createToken(t, anna, "t", map[string][]string{mobility: {"*"}})

	for _, path := range []string{"/v1/me", "/v1/me/tokens", "/v1/me/data"} {
		if r := call(t, "GET", iamURL+path, "", nil); r.Status != 401 {
			t.Fatalf("%s without credentials: %d", path, r.Status)
		}
		if r := call(t, "GET", iamURL+path, tok.Secret, nil); r.Status != 403 || r.errorCode() != "session_required" {
			t.Fatalf("%s with an API token: %d %s", path, r.Status, r.Body)
		}
	}
	if r := createTokenRaw(t, tok.Secret, "escalation", map[string][]string{mobility: {"*"}}); r.Status != 403 {
		t.Fatalf("an API token created another token: %d", r.Status)
	}

	// A valid Keycloak token that is not addressed to this service.
	other := accessToken(t, tokenRequest(t, realm, map[string][]string{
		"grant_type": {"client_credentials"}, "client_id": {"odh-tourism-api"}, "client_secret": {"odh-tourism-api-dev-secret"},
	}, ""))
	if r := call(t, "GET", iamURL+"/v1/me", other, nil); r.Status != 401 {
		t.Fatalf("token for another audience accepted: %d %s", r.Status, r.Body)
	}
}

func TestTokenCarriesOnlyTheSelectedRoles(t *testing.T) {
	anna := login(t, "anna")
	tok := createToken(t, anna, "a22", map[string][]string{mobility: {"BDP_A22"}})

	got := datasets(t, tok.Secret)
	if want := []string{"parking-open", "traffic-a22"}; !reflect.DeepEqual(got.Datasets, want) {
		t.Fatalf("token sees %v, want %v", got.Datasets, want)
	}
	if got.Caller.Kind != "api_token" || got.Caller.Username != "anna" {
		t.Fatalf("caller: %+v", got.Caller)
	}
	if got.Quota != "PREMIUM" {
		t.Fatalf("quota role was not inherited: %s", got.Quota)
	}

	session := datasets(t, anna)
	if want := []string{"parking-open", "traffic-a22", "bluetooth-blc"}; !reflect.DeepEqual(session.Datasets, want) {
		t.Fatalf("session sees %v, want %v", session.Datasets, want)
	}
	if anonymous := datasets(t, ""); !reflect.DeepEqual(anonymous.Datasets, []string{"parking-open"}) || anonymous.Quota != "GUEST" {
		t.Fatalf("anonymous: %+v", anonymous)
	}

	// The token carries no parking role although its owner is an operator.
	if r := call(t, "GET", demoURL+"/parking/scope", tok.Secret, nil); r.Status != 403 {
		t.Fatalf("parking with a timeseries-only token: %d %s", r.Status, r.Body)
	}
	var scope struct {
		Role    string   `json:"role"`
		Origins []string `json:"origins"`
	}
	wide := createToken(t, anna, "parking", map[string][]string{parking: {"operator", "origin:STA"}})
	wantStatus(t, call(t, "GET", demoURL+"/parking/scope", wide.Secret, nil), 200).decode(t, &scope)
	if scope.Role != "operator" || !reflect.DeepEqual(scope.Origins, []string{"STA"}) {
		t.Fatalf("parking scope: %+v", scope)
	}
}

func TestTokenCreationIsValidated(t *testing.T) {
	anna := login(t, "anna")
	cases := map[string]struct {
		name   string
		grants map[string][]string
		status int
		code   string
	}{
		"role not held":     {"x", map[string][]string{mobility: {"BDP_ADMIN"}}, 400, "invalid_grants"},
		"client not an API": {"x", map[string][]string{"realm-management": {"*"}}, 400, "invalid_grants"},
		"empty name":        {"  ", nil, 400, "invalid_name"},
		"name too long":     {strings.Repeat("n", 65), nil, 400, "invalid_name"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := createTokenRaw(t, anna, tc.name, tc.grants)
			if r.Status != tc.status || r.errorCode() != tc.code {
				t.Fatalf("got %d %s", r.Status, r.Body)
			}
		})
	}

	t.Run("duplicate name", func(t *testing.T) {
		name := "dup " + time.Now().Format(time.RFC3339Nano)
		var first struct {
			Token struct {
				ID string `json:"id"`
			} `json:"token"`
		}
		wantStatus(t, createTokenRaw(t, anna, name, nil), 201).decode(t, &first)
		if r := createTokenRaw(t, anna, name, nil); r.Status != 409 || r.errorCode() != "name_taken" {
			t.Fatalf("got %d %s", r.Status, r.Body)
		}
		// A revoked token frees its name.
		wantStatus(t, call(t, "DELETE", iamURL+"/v1/me/tokens/"+first.Token.ID, anna, nil), 204)
		var second struct {
			Token struct {
				ID string `json:"id"`
			} `json:"token"`
		}
		wantStatus(t, createTokenRaw(t, anna, name, nil), 201).decode(t, &second)
		call(t, "DELETE", iamURL+"/v1/me/tokens/"+second.Token.ID, anna, nil)
	})

	t.Run("another user's token cannot be revoked", func(t *testing.T) {
		tok := createToken(t, anna, "mine", nil)
		if r := call(t, "DELETE", iamURL+"/v1/me/tokens/"+tok.ID, login(t, "bob"), nil); r.Status != 404 {
			t.Fatalf("got %d", r.Status)
		}
		if !resolve(t, timeseriesKey, tok.Secret).Active {
			t.Fatal("token was revoked by someone else")
		}
	})
}

func TestRoleChangesReachExistingTokens(t *testing.T) {
	anna := login(t, "anna")
	listed := createToken(t, anna, "listed", map[string][]string{mobility: {"BDP_A22"}})
	wildcard := createToken(t, anna, "wildcard", map[string][]string{mobility: {"*"}})
	kc := admin(t)

	sees := func(tok apiToken, dataset string) bool {
		return slices.Contains(datasets(t, tok.Secret).Datasets, dataset)
	}
	if !sees(listed, "traffic-a22") || !sees(wildcard, "bluetooth-blc") || sees(listed, "bluetooth-blc") {
		t.Fatal("unexpected starting state")
	}

	kc.grant("anna", mobility, "BDP_CBZ")
	eventually(t, "wildcard token gains the new role", func() bool { return sees(wildcard, "sensors-cbz") })
	if sees(listed, "sensors-cbz") {
		t.Fatal("a token with an explicit list gained a role that is not on it")
	}

	kc.withdraw("anna", mobility, "BDP_A22")
	eventually(t, "both tokens lose the withdrawn role", func() bool {
		return !sees(listed, "traffic-a22") && !sees(wildcard, "traffic-a22")
	})
	if !sees(wildcard, "bluetooth-blc") {
		t.Fatal("wildcard token lost a role its owner still holds")
	}
}

func TestRevokedExpiredAndUnknownTokensAreRejected(t *testing.T) {
	anna := login(t, "anna")

	t.Run("revoked", func(t *testing.T) {
		tok := createToken(t, anna, "r", map[string][]string{mobility: {"*"}})
		if datasets(t, tok.Secret).Caller.Kind != "api_token" {
			t.Fatal("token did not work before revocation")
		}
		wantStatus(t, call(t, "DELETE", iamURL+"/v1/me/tokens/"+tok.ID, anna, nil), 204)
		if res := resolve(t, timeseriesKey, tok.Secret); res.Active || res.Reason != "revoked" || res.JWT != "" {
			t.Fatalf("resolve after revocation: %+v", res)
		}
		eventually(t, "resource server rejects the revoked token", func() bool {
			return call(t, "GET", demoURL+"/timeseries/datasets", tok.Secret, nil).Status == 401
		})
		var list []struct {
			ID string `json:"id"`
		}
		wantStatus(t, call(t, "GET", iamURL+"/v1/me/tokens", anna, nil), 200).decode(t, &list)
		for _, item := range list {
			if item.ID == tok.ID {
				t.Fatal("revoked token still listed")
			}
		}
	})

	t.Run("expired", func(t *testing.T) {
		tok := createToken(t, anna, "e", nil)
		if _, err := db(t).Exec(context.Background(),
			`update api_tokens set expires_at = now() - interval '1 second' where id = $1`, tok.ID); err != nil {
			t.Fatal(err)
		}
		if res := resolve(t, timeseriesKey, tok.Secret); res.Active || res.Reason != "expired" {
			t.Fatalf("resolve: %+v", res)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		tok := createToken(t, anna, "w", nil)
		forged := tok.Secret[:len(tok.Secret)-64] + strings.Repeat("0", 64)
		if res := resolve(t, timeseriesKey, forged); res.Active || res.Reason != "unknown" {
			t.Fatalf("resolve: %+v", res)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		if res := resolve(t, timeseriesKey, "odh_pat_nope"); res.Active || res.Reason != "malformed" {
			t.Fatalf("resolve: %+v", res)
		}
		if r := call(t, "GET", demoURL+"/timeseries/datasets", "odh_pat_nope", nil); r.Status != 401 {
			t.Fatalf("resource server: %d", r.Status)
		}
	})
}

func TestDisablingTheOwnerDisablesTheirTokens(t *testing.T) {
	bob := login(t, "bob")
	tok := createToken(t, bob, "b", nil)
	if got := datasets(t, tok.Secret); got.Quota != "BASIC" || got.Caller.Username != "bob" {
		t.Fatalf("before: %+v", got)
	}

	kc := admin(t)
	kc.setEnabled("bob", false)
	t.Cleanup(func() { kc.setEnabled("bob", true) })
	eventually(t, "token of a disabled owner is rejected", func() bool {
		res := resolve(t, timeseriesKey, tok.Secret)
		return !res.Active && res.Reason == "owner_disabled" &&
			call(t, "GET", demoURL+"/timeseries/datasets", tok.Secret, nil).Status == 401
	})

	kc.setEnabled("bob", true)
	eventually(t, "token works again once the owner is re-enabled", func() bool {
		return call(t, "GET", demoURL+"/timeseries/datasets", tok.Secret, nil).Status == 200
	})
}

// umaRoles lists every odh-api-core role the production UMA policies mention.
func umaRoles(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../keycloak/realm-noi-dev.json")
	if err != nil {
		t.Fatal(err)
	}
	var realmFile struct {
		Clients []struct {
			ClientID string `json:"clientId"`
			Authz    struct {
				Policies []struct {
					Type   string            `json:"type"`
					Config map[string]string `json:"config"`
				} `json:"policies"`
			} `json:"authorizationSettings"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(raw, &realmFile); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range realmFile.Clients {
		if c.ClientID != "odh-tourism-api" {
			continue
		}
		for _, p := range c.Authz.Policies {
			if p.Type != "role" {
				continue
			}
			var refs []struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal([]byte(p.Config["roles"]), &refs); err != nil {
				t.Fatal(err)
			}
			for _, ref := range refs {
				if name, ok := strings.CutPrefix(ref.ID, apiCore+"/"); ok {
					seen[name] = true
				}
			}
		}
	}
	var roles []string
	for r := range seen {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	return roles
}

// The service evaluates UMA itself because an API token has no Keycloak
// access token. This checks that evaluation against Keycloak's own answer for
// every role the production policies reference, one at a time and all at once.
func TestContentPermissionsMatchKeycloak(t *testing.T) {
	roles := umaRoles(t)
	if len(roles) != 41 {
		t.Fatalf("fixture references %d roles, expected 41", len(roles))
	}

	compare := func(t *testing.T, username string) map[string][]string {
		t.Helper()
		session := login(t, username)
		tok := createToken(t, session, "uma", map[string][]string{apiCore: {"*"}})
		ours := byResource(resolve(t, contentKey, tok.Secret).Permissions["odh-tourism-api"])
		theirs := umaPermissions(t, session)
		if !reflect.DeepEqual(ours, theirs) {
			t.Fatalf("permissions differ\n service:  %v\n keycloak: %v", ours, theirs)
		}
		return ours
	}

	t.Run("no roles", func(t *testing.T) {
		if got := compare(t, "bob"); len(got) != 0 {
			t.Fatalf("bob has permissions: %v", got)
		}
	})
	t.Run("anna", func(t *testing.T) { compare(t, "anna") })
	t.Run("walter", func(t *testing.T) {
		if got := compare(t, "walter"); len(got) != 32 {
			t.Fatalf("DataWriter covers %d resources, want 32", len(got))
		}
	})
	var grantNothing []string
	for _, role := range roles {
		t.Run("single role "+role, func(t *testing.T) {
			// Bound to the subtest, so the role is withdrawn before the next one.
			admin(t).grant("bob", apiCore, role)
			if got := compare(t, "bob"); len(got) == 0 {
				grantNothing = append(grantNothing, role)
			}
		})
	}
	// The production configuration has a policy for STA that no permission uses.
	if want := []string{"STA"}; !reflect.DeepEqual(grantNothing, want) {
		t.Fatalf("roles granting nothing: %v, want %v", grantNothing, want)
	}
	t.Run("all roles together", func(t *testing.T) {
		admin(t).grant("bob", apiCore, roles...)
		compare(t, "bob")
	})
}

func TestRestrictedTokenOnTheContentAPI(t *testing.T) {
	anna := login(t, "anna")
	tok := createToken(t, anna, "articles", map[string][]string{apiCore: {"ArticleNOIManager"}})

	got := byResource(resolve(t, contentKey, tok.Secret).Permissions["odh-tourism-api"])
	want := map[string][]string{"Article?source=noi": {"Create", "Delete", "Update"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}

	create := func(bearer, entity, source string) int {
		return call(t, "POST", demoURL+"/content/"+entity+"?source="+source, bearer, map[string]any{}).Status
	}
	if s := create(tok.Secret, "Article", "noi"); s != 201 {
		t.Fatalf("token on its own resource: %d", s)
	}
	if s := create(tok.Secret, "Article", "lts"); s != 403 {
		t.Fatalf("token on another source: %d", s)
	}
	if s := create(tok.Secret, "Event", "noi"); s != 403 {
		t.Fatalf("token on a role it does not carry: %d", s)
	}
	// The same request with the owner's session goes through Keycloak UMA.
	if s := create(anna, "Event", "noi"); s != 201 {
		t.Fatalf("session: %d", s)
	}
	if s := create("", "Article", "noi"); s != 401 {
		t.Fatalf("anonymous write: %d", s)
	}

	var read struct {
		AccessRoles []string `json:"accessRoles"`
	}
	idm := createToken(t, anna, "idm", map[string][]string{apiCore: {"IDM"}})
	wantStatus(t, call(t, "GET", demoURL+"/content/Accommodation", idm.Secret, nil), 200).decode(t, &read)
	if want := []string{"ANONYMOUS", "IDM"}; !reflect.DeepEqual(read.AccessRoles, want) {
		t.Fatalf("IDM token reads as %v", read.AccessRoles)
	}
	wantStatus(t, call(t, "GET", demoURL+"/content/Accommodation", tok.Secret, nil), 200).decode(t, &read)
	if want := []string{"ANONYMOUS"}; !reflect.DeepEqual(read.AccessRoles, want) {
		t.Fatalf("article token reads as %v", read.AccessRoles)
	}
}

func TestIssuedJWT(t *testing.T) {
	ctx := context.Background()
	walter := login(t, "walter")
	tok := createToken(t, walter, "all", map[string][]string{mobility: {"*"}, apiCore: {"*"}})

	// Standard OIDC discovery, as a Spring or .NET resource server would do.
	provider, err := oidc.NewProvider(ctx, iamURL)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}

	type claims struct {
		Subject        string   `json:"sub"`
		Username       string   `json:"preferred_username"`
		AuthorizedBy   string   `json:"azp"`
		Type           string   `json:"typ"`
		TokenID        string   `json:"odh_token_id"`
		Flat           []string `json:"role"`
		ResourceAccess map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
	}

	res := resolve(t, timeseriesKey, tok.Secret)
	verified, err := provider.Verifier(&oidc.Config{ClientID: mobility}).Verify(ctx, res.JWT)
	if err != nil {
		t.Fatalf("verifying the issued JWT: %v", err)
	}
	var c claims
	if err := verified.Claims(&c); err != nil {
		t.Fatal(err)
	}
	if c.Subject != admin(t).userID("walter") || c.Username != "walter" || c.AuthorizedBy != "odh-iam" || c.Type != "Bearer" || c.TokenID != tok.ID {
		t.Fatalf("claims: %+v", c)
	}
	if len(c.ResourceAccess) != 1 || !reflect.DeepEqual(c.ResourceAccess[mobility].Roles, []string{"BDP_ADMIN", "ODH_ROLE_ADMIN"}) {
		t.Fatalf("resource_access must hold only this audience's roles: %+v", c.ResourceAccess)
	}
	if ttl := time.Until(verified.Expiry); ttl <= 0 || ttl > 61*time.Second {
		t.Fatalf("lifetime %s", ttl)
	}
	if !reflect.DeepEqual(res.Roles, map[string][]string{mobility: {"BDP_ADMIN", "ODH_ROLE_ADMIN"}}) {
		t.Fatalf("roles: %v", res.Roles)
	}
	if res.Permissions != nil {
		t.Fatal("timeseries received UMA permissions it did not ask for")
	}

	content := resolve(t, contentKey, tok.Secret)
	verified, err = provider.Verifier(&oidc.Config{ClientID: apiCore}).Verify(ctx, content.JWT)
	if err != nil {
		t.Fatal(err)
	}
	c = claims{}
	_ = verified.Claims(&c)
	if !reflect.DeepEqual(c.Flat, []string{"DataWriter"}) {
		t.Fatalf("flat role claim: %v", c.Flat)
	}

	t.Run("a JWT is only good for its audience", func(t *testing.T) {
		if _, err := provider.Verifier(&oidc.Config{ClientID: apiCore}).Verify(ctx, res.JWT); err == nil {
			t.Fatal("timeseries JWT verified for the content audience")
		}
	})

	t.Run("the edge accepts an internal JWT for its audience", func(t *testing.T) {
		got := datasets(t, res.JWT)
		if got.Caller.Kind != "api_token" || got.Caller.Subject != c.Subject || got.Caller.TokenID != tok.ID {
			t.Fatalf("caller: %+v", got.Caller)
		}
		wantStatus(t, call(t, "GET", demoURL+"/content/permissions", res.JWT, nil), 401)
		passed := resolve(t, timeseriesKey, res.JWT)
		if !passed.Active || passed.JWT != res.JWT {
			t.Fatalf("pass-through: %+v", passed)
		}
	})
	t.Run("session claims mirror Keycloak", func(t *testing.T) {
		session := resolve(t, timeseriesKey, walter)
		verified, err := provider.Verifier(&oidc.Config{ClientID: mobility}).Verify(ctx, session.JWT)
		if err != nil {
			t.Fatal(err)
		}
		var c claims
		if err := verified.Claims(&c); err != nil {
			t.Fatal(err)
		}
		if c.AuthorizedBy != "odh-iam-ui" {
			t.Fatalf("azp: %s", c.AuthorizedBy)
		}
		parts := strings.Split(walter, ".")
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var original struct {
			Audience json.RawMessage `json:"aud"`
		}
		if err := json.Unmarshal(raw, &original); err != nil {
			t.Fatal(err)
		}
		var audiences []string
		if json.Unmarshal(original.Audience, &audiences) != nil {
			var a string
			if err := json.Unmarshal(original.Audience, &a); err != nil {
				t.Fatal(err)
			}
			audiences = []string{a}
		}
		for _, a := range append(audiences, mobility) {
			if !slices.Contains(verified.Audience, a) {
				t.Fatalf("missing %s in %v", a, verified.Audience)
			}
		}
	})

}

func TestResolveNeedsAServiceKey(t *testing.T) {
	anna := login(t, "anna")
	tok := createToken(t, anna, "k", nil)
	body := map[string]any{"token": tok.Secret}
	for name, key := range map[string]string{"none": "", "wrong": "not-a-service-key-at-all", "user session": anna, "api token": tok.Secret} {
		if r := call(t, "POST", iamURL+"/v1/resolve", key, body); r.Status != 401 {
			t.Fatalf("%s: %d %s", name, r.Status, r.Body)
		}
	}
	if r := call(t, "POST", iamURL+"/v1/resolve", timeseriesKey, map[string]any{}); r.Status != 400 {
		t.Fatalf("empty body: %d", r.Status)
	}
}

func TestUserData(t *testing.T) {
	anna, bob := login(t, "anna"), login(t, "bob")
	prefs := map[string]any{"language": "it", "theme": "dark"}
	t.Cleanup(func() {
		call(t, "DELETE", iamURL+"/v1/me/data/preferences", anna, nil)
		call(t, "DELETE", iamURL+"/v1/me/data/profile", anna, nil)
	})

	wantStatus(t, call(t, "PUT", iamURL+"/v1/me/data/preferences", anna, prefs), 200)
	wantStatus(t, call(t, "PUT", iamURL+"/v1/me/data/profile", anna, map[string]any{"organisation": "NOI"}), 200)

	var got map[string]any
	wantStatus(t, call(t, "GET", iamURL+"/v1/me/data/preferences", anna, nil), 200).decode(t, &got)
	if !reflect.DeepEqual(got, prefs) {
		t.Fatalf("got %v", got)
	}
	var all map[string]map[string]any
	wantStatus(t, call(t, "GET", iamURL+"/v1/me/data", anna, nil), 200).decode(t, &all)
	if len(all) != 2 || all["profile"]["organisation"] != "NOI" {
		t.Fatalf("all: %v", all)
	}

	t.Run("data is per user", func(t *testing.T) {
		if r := call(t, "GET", iamURL+"/v1/me/data/preferences", bob, nil); r.Status != 404 {
			t.Fatalf("bob read %d %s", r.Status, r.Body)
		}
	})

	t.Run("replaced on write", func(t *testing.T) {
		wantStatus(t, call(t, "PUT", iamURL+"/v1/me/data/profile", anna, map[string]any{"team": "ODH"}), 200)
		var profile map[string]any
		wantStatus(t, call(t, "GET", iamURL+"/v1/me/data/profile", anna, nil), 200).decode(t, &profile)
		if !reflect.DeepEqual(profile, map[string]any{"team": "ODH"}) {
			t.Fatalf("profile: %v", profile)
		}
	})

	t.Run("input is validated", func(t *testing.T) {
		if r := call(t, "PUT", iamURL+"/v1/me/data/Bad%20Name", anna, prefs); r.Status != 400 {
			t.Fatalf("namespace: %d", r.Status)
		}
		if r := call(t, "PUT", iamURL+"/v1/me/data/preferences", anna, []byte(`["not","an","object"]`)); r.Status != 400 {
			t.Fatalf("array: %d", r.Status)
		}
		big := map[string]any{"blob": strings.Repeat("x", 70<<10)}
		if r := call(t, "PUT", iamURL+"/v1/me/data/preferences", anna, big); r.Status != 413 {
			t.Fatalf("oversized: %d", r.Status)
		}
	})

	tok := createToken(t, anna, "h", nil)
	subject := resolve(t, timeseriesKey, anna).Principal.Subject
	path := iamURL + "/v1/users/" + subject + "/data/"
	t.Run("a service reads a namespace by subject", func(t *testing.T) {
		for _, key := range []string{timeseriesKey, contentKey} {
			var data map[string]any
			wantStatus(t, call(t, "GET", path+"preferences", key, nil), 200).decode(t, &data)
			if !reflect.DeepEqual(data, prefs) {
				t.Fatalf("data: %v", data)
			}
			wantStatus(t, call(t, "GET", path+"profile", key, nil), 200)
		}
	})
	t.Run("unknown namespace is not found", func(t *testing.T) {
		var body map[string]any
		wantStatus(t, call(t, "GET", path+"unknown", timeseriesKey, nil), 404).decode(t, &body)
		if body["error"] != "not_found" {
			t.Fatalf("error: %v", body)
		}
	})
	t.Run("invalid namespace is rejected", func(t *testing.T) {
		var body map[string]any
		wantStatus(t, call(t, "GET", path+"Bad%20Name", timeseriesKey, nil), 400).decode(t, &body)
		if body["error"] != "invalid_namespace" {
			t.Fatalf("error: %v", body)
		}
	})
	t.Run("only service keys can read by subject", func(t *testing.T) {
		for _, bearer := range []string{"", anna, tok.Secret} {
			wantStatus(t, call(t, "GET", path+"preferences", bearer, nil), 401)
		}
	})
	t.Run("include is ignored and user data is absent", func(t *testing.T) {
		for _, bearer := range []string{anna, tok.Secret} {
			res := resolve(t, timeseriesKey, bearer)
			var body map[string]json.RawMessage
			wantStatus(t, call(t, "POST", iamURL+"/v1/resolve", timeseriesKey, map[string]any{"token": bearer, "include": []string{"preferences"}}), 200).decode(t, &body)
			if _, exists := body["data"]; exists {
				t.Fatal("resolution contains data")
			}
			if !res.Active {
				t.Fatalf("resolution: %+v", res)
			}
		}
	})
	t.Run("resource server reads preferences for both credentials", func(t *testing.T) {
		for name, bearer := range map[string]string{"api token": tok.Secret, "session": anna, "no data": bob} {
			var me struct {
				Caller      demoCaller     `json:"caller"`
				Preferences map[string]any `json:"preferences"`
			}
			wantStatus(t, call(t, "GET", demoURL+"/timeseries/me", bearer, nil), 200).decode(t, &me)
			if name == "no data" {
				if me.Preferences != nil {
					t.Fatalf("preferences: %v", me.Preferences)
				}
			} else if me.Caller.Username != "anna" || !reflect.DeepEqual(me.Preferences, prefs) {
				t.Fatalf("%s: %+v", name, me)
			}
		}
	})
}

func TestOnlyAHashOfTheSecretIsStored(t *testing.T) {
	anna := login(t, "anna")
	tok := createToken(t, anna, "s", nil)
	secret := tok.Secret[strings.LastIndex(tok.Secret, "_")+1:]

	var hash []byte
	var row string
	if err := db(t).QueryRow(context.Background(),
		`select secret_hash, t::text from api_tokens t where id = $1`, tok.ID).Scan(&hash, &row); err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256([]byte(secret)); !reflect.DeepEqual(hash, want[:]) {
		t.Fatal("stored hash is not SHA-256 of the secret")
	}
	if strings.Contains(row, secret) {
		t.Fatal("the row contains the secret in clear")
	}

	var list []map[string]any
	wantStatus(t, call(t, "GET", iamURL+"/v1/me/tokens", anna, nil), 200).decode(t, &list)
	if strings.Contains(string(mustJSON(t, list)), secret) {
		t.Fatal("the token list reveals a secret")
	}
}

func TestLastUseIsRecorded(t *testing.T) {
	anna := login(t, "anna")
	tok := createToken(t, anna, "u", nil)
	find := func() *time.Time {
		var list []struct {
			ID         string     `json:"id"`
			LastUsedAt *time.Time `json:"lastUsedAt"`
		}
		wantStatus(t, call(t, "GET", iamURL+"/v1/me/tokens", anna, nil), 200).decode(t, &list)
		for _, item := range list {
			if item.ID == tok.ID {
				return item.LastUsedAt
			}
		}
		t.Fatal("token not listed")
		return nil
	}
	if find() != nil {
		t.Fatal("unused token has a last-use time")
	}
	datasets(t, tok.Secret)
	if at := find(); at == nil || time.Since(*at) > time.Minute {
		t.Fatalf("last use: %v", at)
	}
}

// The APIs behind the edge know one issuer. Whatever credential a client
// sends, the API receives a JWT signed by the identity service, and a
// session is re-read from Keycloak like an API token is.
func TestEdgeNormalizesEveryCredential(t *testing.T) {
	anna := login(t, "anna")
	tok := createToken(t, anna, "edge", map[string][]string{mobility: {"*"}})

	t.Run("anonymous passes through", func(t *testing.T) {
		got := datasets(t, "")
		if got.Caller.Kind != "anonymous" || got.Quota != "GUEST" || !reflect.DeepEqual(got.Datasets, []string{"parking-open"}) {
			t.Fatalf("%+v", got)
		}
	})

	t.Run("a Keycloak session and an API token arrive as the same shape", func(t *testing.T) {
		session, token := datasets(t, anna), datasets(t, tok.Secret)
		if session.Caller.Kind != "session" || token.Caller.Kind != "api_token" {
			t.Fatalf("kinds: %s %s", session.Caller.Kind, token.Caller.Kind)
		}
		if session.Caller.Subject != token.Caller.Subject || token.Caller.TokenID != tok.ID {
			t.Fatalf("session %+v token %+v", session.Caller, token.Caller)
		}
		if !reflect.DeepEqual(session.Datasets, token.Datasets) {
			t.Fatalf("a wildcard token must see what its owner sees: %v vs %v", token.Datasets, session.Datasets)
		}
	})

	t.Run("a client_credentials token works unchanged", func(t *testing.T) {
		machine := accessToken(t, tokenRequest(t, realm, map[string][]string{
			"grant_type": {"client_credentials"}, "client_id": {"odh-tourism-api"}, "client_secret": {"odh-tourism-api-dev-secret"},
		}, ""))
		got := datasets(t, machine)
		if got.Caller.Kind != "session" || got.Caller.Username != "service-account-odh-tourism-api" || got.Quota != "BASIC" {
			t.Fatalf("%+v", got)
		}
	})

	t.Run("a role change reaches a session without a new login", func(t *testing.T) {
		if slices.Contains(datasets(t, anna).Datasets, "sensors-cbz") {
			t.Fatal("unexpected starting state")
		}
		admin(t).grant("anna", mobility, "BDP_CBZ")
		eventually(t, "the same session token sees the new role", func() bool {
			return slices.Contains(datasets(t, anna).Datasets, "sensors-cbz")
		})
	})

	t.Run("garbage credentials are rejected at the edge", func(t *testing.T) {
		for _, cred := range []string{"nonsense", anna + "x", "odh_pat_short"} {
			if r := call(t, "GET", demoURL+"/timeseries/datasets", cred, nil); r.Status != 401 {
				t.Fatalf("%q: %d", cred, r.Status)
			}
		}
	})
}

func TestClientCredentialsTokenEndpoint(t *testing.T) {
	ctx := context.Background()
	cfg := clientcredentials.Config{ClientID: "odh-tourism-api", ClientSecret: "odh-tourism-api-dev-secret", TokenURL: iamURL + "/v1/token"}
	token, err := cfg.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oidc.NewProvider(ctx, iamURL)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := provider.Verifier(&oidc.Config{ClientID: mobility}).Verify(ctx, token.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Azp  string          `json:"azp"`
		Kind string          `json:"odh_principal"`
		Data json.RawMessage `json:"odh_data"`
	}
	if err := verified.Claims(&c); err != nil {
		t.Fatal(err)
	}
	if verified.Issuer != iamURL || c.Azp != cfg.ClientID || c.Kind != "client" || len(c.Data) != 0 {
		t.Fatalf("claims: %+v", c)
	}
	for _, a := range []string{mobility, apiCore, parking} {
		if !slices.Contains(verified.Audience, a) {
			t.Fatalf("audiences: %v", verified.Audience)
		}
	}
	if ttl := time.Until(verified.Expiry); ttl <= 0 || ttl > 5*time.Minute {
		t.Fatalf("lifetime: %s", ttl)
	}
	got := datasets(t, token.AccessToken)
	if got.Caller.Kind != "client" || got.Caller.Username != "service-account-odh-tourism-api" {
		t.Fatalf("caller: %+v", got.Caller)
	}
	cfg.AuthStyle = oauth2.AuthStyleInParams
	if _, err := cfg.Token(ctx); err != nil {
		t.Fatalf("form credentials: %v", err)
	}
	cfg.ClientSecret = "wrong"
	_, err = cfg.Token(ctx)
	var oauthErr *oauth2.RetrieveError
	if !errors.As(err, &oauthErr) || oauthErr.Response.StatusCode != 401 || oauthErr.ErrorCode == "" {
		t.Fatalf("wrong secret: %v", err)
	}
	resp, err := client.PostForm(iamURL+"/v1/token", url.Values{"grant_type": {"password"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var failure struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&failure); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest || failure.Error != "unsupported_grant_type" {
		t.Fatalf("unsupported grant: %d %+v", resp.StatusCode, failure)
	}
}
