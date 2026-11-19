// Package keycloak is the read-only view of Keycloak this service needs:
// who a user is, which roles they hold now, and a client's UMA configuration.
package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/sync/errgroup"

	"github.com/noi-techpark/opendatahub-go-sdk/tel/stdhttp"
)

var ErrNotFound = errors.New("keycloak: not found")

type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Enabled   bool   `json:"enabled"`
}

type Admin struct {
	base string
	http *http.Client

	mu    sync.Mutex
	uuids map[string]string
}

func NewAdmin(baseURL, realm, clientID, clientSecret string) *Admin {
	cc := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", baseURL, realm),
	}
	// oauth2 takes the base client, and so the tracing transport, from the context.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: stdhttp.Transport(nil)})
	client := cc.Client(ctx)
	client.Timeout = 10 * time.Second
	return &Admin{
		base:  fmt.Sprintf("%s/admin/realms/%s", baseURL, realm),
		http:  client,
		uuids: map[string]string{},
	}
}

func (a *Admin) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("keycloak: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("keycloak: GET %s: %s", path, resp.Status)
	}
	return body, nil
}

func (a *Admin) User(ctx context.Context, id string) (User, error) {
	var u User
	body, err := a.get(ctx, "/users/"+url.PathEscape(id))
	if err != nil {
		return u, err
	}
	return u, json.Unmarshal(body, &u)
}

// UserByUsername finds a user by exact username.
func (a *Admin) UserByUsername(ctx context.Context, username string) (User, error) {
	body, err := a.get(ctx, "/users?exact=true&username="+url.QueryEscape(username))
	if err != nil {
		return User{}, err
	}
	var found []User
	if err := json.Unmarshal(body, &found); err != nil {
		return User{}, err
	}
	if len(found) != 1 {
		return User{}, ErrNotFound
	}
	return found[0], nil
}

func (a *Admin) clientUUID(ctx context.Context, clientID string) (string, error) {
	a.mu.Lock()
	uuid, ok := a.uuids[clientID]
	a.mu.Unlock()
	if ok {
		return uuid, nil
	}
	body, err := a.get(ctx, "/clients?clientId="+url.QueryEscape(clientID))
	if err != nil {
		return "", err
	}
	var found []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &found); err != nil {
		return "", err
	}
	if len(found) != 1 {
		return "", fmt.Errorf("keycloak: client %q: %w", clientID, ErrNotFound)
	}
	a.mu.Lock()
	a.uuids[clientID] = found[0].ID
	a.mu.Unlock()
	return found[0].ID, nil
}

// EffectiveClientRoles returns the roles a user holds on a client, including
// those reached through composite roles and group membership.
func (a *Admin) EffectiveClientRoles(ctx context.Context, userID, clientID string) ([]string, error) {
	uuid, err := a.clientUUID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	body, err := a.get(ctx, fmt.Sprintf("/users/%s/role-mappings/clients/%s/composite", url.PathEscape(userID), uuid))
	if err != nil {
		return nil, err
	}
	var roles []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &roles); err != nil {
		return nil, err
	}
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	return names, nil
}

// AuthzSettings assembles a client's UMA configuration in the shape of
// Keycloak's settings export. The export endpoint itself needs a manage role;
// these list endpoints need only view-authorization.
func (a *Admin) AuthzSettings(ctx context.Context, clientID string) ([]byte, error) {
	uuid, err := a.clientUUID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	base := "/clients/" + uuid + "/authz/resource-server"

	var doc struct {
		PolicyEnforcementMode string            `json:"policyEnforcementMode"`
		DecisionStrategy      string            `json:"decisionStrategy"`
		Resources             []json.RawMessage `json:"resources"`
		Policies              []authzPolicy     `json:"policies"`
	}
	if err := a.getJSON(ctx, base, &doc); err != nil {
		return nil, err
	}
	if doc.Resources, err = pages[json.RawMessage](ctx, a, base+"/resource?deep=true"); err != nil {
		return nil, err
	}
	if doc.Policies, err = pages[authzPolicy](ctx, a, base+"/policy?permission=false"); err != nil {
		return nil, err
	}
	permissions, err := pages[authzPolicy](ctx, a, base+"/permission?")
	if err != nil {
		return nil, err
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(8)
	for i := range doc.Policies {
		p := &doc.Policies[i]
		if p.Type != "role" {
			continue
		}
		g.Go(func() error {
			var refs []map[string]any
			if err := json.Unmarshal([]byte(p.Config["roles"]), &refs); err != nil {
				return fmt.Errorf("keycloak: policy %q: %w", p.Name, err)
			}
			for _, ref := range refs {
				id, _ := ref["id"].(string)
				name, err := a.roleName(gctx, id)
				if err != nil {
					return err
				}
				ref["id"] = name
			}
			raw, _ := json.Marshal(refs)
			p.Config = map[string]string{"roles": string(raw)}
			return nil
		})
	}
	for i := range permissions {
		p := &permissions[i]
		g.Go(func() error {
			p.Config = map[string]string{}
			for key, path := range map[string]string{
				"resources":     "/resources",
				"scopes":        "/scopes",
				"applyPolicies": "/associatedPolicies",
			} {
				var items []struct {
					Name string `json:"name"`
				}
				if err := a.getJSON(gctx, base+"/policy/"+p.ID+path, &items); err != nil {
					return err
				}
				if len(items) == 0 {
					continue
				}
				names := make([]string, len(items))
				for j, item := range items {
					names[j] = item.Name
				}
				raw, _ := json.Marshal(names)
				p.Config[key] = string(raw)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	doc.Policies = append(doc.Policies, permissions...)
	return json.Marshal(doc)
}

type authzPolicy struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Type             string            `json:"type"`
	Logic            string            `json:"logic"`
	DecisionStrategy string            `json:"decisionStrategy"`
	Config           map[string]string `json:"config"`
}

func (a *Admin) getJSON(ctx context.Context, path string, into any) error {
	body, err := a.get(ctx, path)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, into)
}

func pages[T any](ctx context.Context, a *Admin, path string) ([]T, error) {
	const size = 200
	var all []T
	for first := 0; ; first += size {
		var page []T
		if err := a.getJSON(ctx, fmt.Sprintf("%s&first=%d&max=%d", path, first, size), &page); err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < size {
			return all, nil
		}
	}
}

// roleName returns a role in export form: "client/role", or the bare name
// for a realm role.
func (a *Admin) roleName(ctx context.Context, id string) (string, error) {
	var role struct {
		Name        string `json:"name"`
		ClientRole  bool   `json:"clientRole"`
		ContainerID string `json:"containerId"`
	}
	if err := a.getJSON(ctx, "/roles-by-id/"+url.PathEscape(id), &role); err != nil {
		return "", err
	}
	if !role.ClientRole {
		return role.Name, nil
	}
	var client struct {
		ClientID string `json:"clientId"`
	}
	if err := a.getJSON(ctx, "/clients/"+url.PathEscape(role.ContainerID), &client); err != nil {
		return "", err
	}
	return client.ClientID + "/" + role.Name, nil
}
