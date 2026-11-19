# ODH identity service

Keycloak stays the identity provider: it logs users in and holds who has which
role. This service adds what Keycloak does not offer:

- **API tokens** users issue for themselves, limited to a subset of their own
  roles, revocable, and always reflecting the owner's current roles.
- **User data** that does not belong in Keycloak (settings, preferences,
  profile), which resource servers can read on demand.

It owns no permission model. A token carries role names; each API keeps
interpreting those names the way it does today.

It is the **only token issuer the APIs know**. An ingress hook asks the
service to resolve whatever credential arrived (Keycloak session, machine
client, API token, nothing) and forwards the request with a JWT this service
signed. Keycloak logs users in and holds role assignments; its tokens never
reach an API.

## Run it

```sh
make up        # Keycloak, Postgres, the service, the edge, the demo APIs
make test      # unit tests
make e2e       # API suite + browser suite against the running stack
make down
```

With rootless podman instead of Docker, see the header of the `Makefile`.

| URL | What |
|---|---|
| http://localhost:4010 | console (sign in as `anna`, `walter` or `bob`; password = username). The console is a demo frontend kept outside this repository for now; without it the service serves `web/README.md` |
| http://localhost:4011 | the edge (nginx `auth_request`) in front of the demo APIs for timeseries, content and parking |
| http://localhost:8180 | Keycloak, realm `noi` (admin console: `admin` / `admin`) |

The demo APIs themselves are not published on the host: they accept only JWTs
signed by this service, which callers can obtain through the edge or the token endpoint.

The dev realm (`keycloak/realm-noi-dev.json`) is generated from a partial
export of the real realm by `scripts/gen-realm.py`. It keeps the four API
clients, their roles and the complete `odh-tourism-api` UMA configuration, and
adds the service's two clients and three test users.

Keycloak keeps its dev data inside the container. Recreating that container
re-imports the realm with new user ids, which orphans tokens created before.

## How a token works

```
odh_pat_<16 hex id>_<64 hex secret>
```

The row stores the id, a SHA-256 of the secret, the owner's Keycloak user id
and an allow-list such as:

```json
{ "odh-mobility-v2": ["BDP_A22"], "odh-api-core": ["*"] }
```

On every `resolve` the service reads the owner's roles from Keycloak and keeps
the ones the allow-list permits. `"*"` means every role on that client,
including roles granted later. Nothing is copied into Keycloak.

- A role removed from the owner disappears from the token.
- A role added to the owner is carried only where the list says `"*"`.
- Roles matching `inheritedRoles` (the `ODH_ROLE_*` quota tiers) are always
  carried and cannot be deselected.
- Only roles on the clients listed in `apiClients` are eligible.
- A disabled or deleted owner invalidates all their tokens.

Sessions are treated the same way: a Keycloak access token is verified, then
the user's roles are re-read from Keycloak rather than taken from the token,
so a role change reaches an open session and an API token with the same
delay. Changes arrive after at most `IAM_CACHE_TTL` (15 s) plus the lifetime
of the JWT the API already holds (`IAM_JWT_TTL`, 60 s).

## The request path

```
client ──(any credential)──▶ ingress ──forward-auth──▶ odh-iam ──▶ Keycloak admin API
                                │◀── 200 + Authorization: Bearer <odh-iam jwt> ──┘
                                └──(that jwt)──▶ API
```

1. The ingress calls `GET /v1/forward-auth/{service}` with the client's
   headers and its service key in `X-Service-Key`. `edge/nginx.conf` is the
   nginx version, the same directives ingress-nginx's `auth-url` and
   `auth-response-headers` annotations generate; Traefik `forwardAuth` and
   Envoy `ext_authz` work the same way.
2. The service resolves the credential: a Keycloak token is verified and the
   user re-read; an `odh_pat_` token is looked up, checked and intersected with
   the owner's roles; this service's own JWT is verified and passed through
   unchanged if its audience includes the target; no credential passes through
   as anonymous.
3. It answers 200 with an `Authorization` header holding a JWT for that API's
   audience, or 401. The ingress replaces the client's header and forwards.
4. The API verifies the JWT against this service's JWKS and reads roles from
   it. Discovery and JWKS are at the standard paths, so Spring's
   `issuer-uri`, .NET's `Authority` and `go-oidc` work by changing one URL
   from Keycloak's issuer to `IAM_PUBLIC_URL`.
5. A frontend reads user data with its session through `/v1/me/data`. An API
   that needs it calls `GET /v1/users/{subject}/data/{namespace}` with its
   service key and the JWT's `sub`, and caches the answer.

The JWT mirrors a Keycloak access token (`sub`, `typ`, `preferred_username`,
`email`, `resource_access.<client>.roles`, an optional flat role claim).
`azp` passes through from Keycloak; API tokens use `IAM_KEYCLOAK_CLIENT_ID`
(`odh-iam`). `aud` contains Keycloak's audiences plus the target API's,
de-duplicated with the target last; API tokens carry only the target.
It adds `odh_principal` (`session`, `client` or `api_token`),
`odh_token_id` and `odh_permissions` for services with `uma`. User data is
never in the JWT. Hook JWTs live 60 s.

Machine clients call `POST /v1/token` with a `client_credentials` form grant
and HTTP Basic or form credentials. Keycloak authenticates them; the service
returns one JWT for all configured services, with their roles and UMA
permissions, no user data, and a default lifetime of five minutes. It can be
sent directly to an API or through the hook.

`cmd/demo-api` is a resource server in the three authorization styles the real
APIs use. Its whole integration is `newAPI` and `authenticate`.

An API must not be reachable except through the ingress. The forward-auth
route checks `X-Service-Key`; inside a cluster it should also be restricted
to the ingress by network policy.

Two properties of `auth_request` to know: a rejected credential is answered
by the proxy, not the API, so the edge adds the CORS header a browser needs
on that 401; and any answer from the service other than 2xx, 401 or 403, a
503 while Keycloak is down for instance, becomes a 500 at the edge.

The hook is not tied to the cluster. Browser frontends and scripts send their
credential to the API host and never see this service. A system with its own
backend elsewhere runs the same hook at its own edge (nginx `auth_request`,
Caddy `forward_auth`) against the public host and verifies the same JWKS; it
then needs a caller credential instead of a network policy. See
`docs/architecture.html` for the topologies, the deployment and that case.

`POST /v1/resolve` returns the same resolution as JSON for anything that is
not an ingress: tests, tooling, or an IAP such as Ory Oathkeeper used in place
of the forward-auth endpoint (`bearer_token` authenticator and `hydrator`
mutator pointed at it).

```sh
curl -s localhost:4010/v1/resolve \
  -H 'Authorization: Bearer dev-timeseries-service-key' \
  -H 'Content-Type: application/json' \
  -d '{"token":"odh_pat_…"}'
```

```json
{
  "active": true,
  "principal": { "kind": "api_token", "sub": "…", "username": "anna", "tokenId": "…", "tokenName": "ci" },
  "roles": { "odh-mobility-v2": ["BDP_A22", "ODH_ROLE_PREMIUM"] },
  "jwt": "eyJ…",
  "expiresIn": 60
}
```

### Content API: UMA permissions

Keycloak evaluates UMA only against one of its own access tokens, which never
reach the content API in this topology. For services with `uma` configured,
the service therefore returns `permissions` in the shape of Keycloak's
`response_mode=permissions`, computed from the caller's roles and the client's
UMA configuration, for sessions and API tokens alike. Keycloak's Authorization
tab stays the place where those permissions are edited.

`internal/uma` reproduces only what role-based configurations use: positive
role policies, scope and resource permissions that name their resources, and an
affirmative resource server. Anything else makes `resolve` fail with 503 for
that service rather than evaluate it approximately.

The configuration is read through Keycloak's list endpoints, which need only
`view-authorization`; the single-call export needs a manage role. It is cached
for `IAM_POLICY_TTL` (60 s).

## API

Self-service, with the user's Keycloak access token (audience
`IAM_SESSION_AUDIENCE`). API tokens are refused here, so a token can neither
mint tokens nor read its owner's data.

| | |
|---|---|
| `GET /v1/me` | identity and current roles per API |
| `GET /v1/me/tokens` | active tokens, with what each carries now |
| `POST /v1/me/tokens` | `{name, grants, expiresInDays?}` → the secret, once |
| `DELETE /v1/me/tokens/{id}` | revoke |
| `GET /v1/me/data` | all namespaces |
| `GET` `PUT` `DELETE /v1/me/data/{namespace}` | one JSON object per namespace, 64 KiB, 32 namespaces |

For the ingress and resource servers, with a service key:

| | |
|---|---|
| `GET /v1/forward-auth/{service}` | ingress hook, `X-Service-Key` header: 200 + `Authorization` header, or 401 |
| `POST /v1/resolve` | `{token}` → the same resolution as JSON |
| `GET /v1/users/{subject}/data/{namespace}` | one stored JSON object, Bearer service key; 404 if absent |

Machine clients, authenticated by Keycloak:

| | |
|---|---|
| `POST /v1/token` | `client_credentials` form grant → Bearer JWT for all services |

Public: `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/healthz`.

## Configuration

| Variable | Default | |
|---|---|---|
| `IAM_DATABASE_URL` | required | Postgres |
| `IAM_KEYCLOAK_CLIENT_SECRET` | required | secret of `IAM_KEYCLOAK_CLIENT_ID` |
| `IAM_PUBLIC_URL` | `http://localhost:4010` | issuer of the JWTs this service signs |
| `IAM_KEYCLOAK_URL` | `http://localhost:8180` | base URL, including `/auth` where Keycloak uses it |
| `IAM_KEYCLOAK_ISSUER` | derived | `iss` of user tokens, when it differs from the URL above |
| `IAM_KEYCLOAK_REALM` | `noi` | |
| `IAM_KEYCLOAK_CLIENT_ID` | `odh-iam` | service account used to read Keycloak |
| `IAM_SESSION_AUDIENCE` | `odh-iam` | `aud` required on self-service calls |
| `IAM_UI_CLIENT_ID` | `odh-iam-ui` | public client the console logs in with |
| `IAM_SIGNING_KEY_FILE` | `data/signing-key.pem` | RSA key, created on first start |
| `IAM_CONFIG` | `config/dev.json` | API clients, inherited roles, services |
| `IAM_CACHE_TTL` | `15s` | user and role cache |
| `IAM_POLICY_TTL` | `60s` | UMA configuration cache |
| `IAM_JWT_TTL` | `60s` | lifetime of hook JWTs |
| `IAM_CLIENT_TOKEN_TTL` | `5m` | lifetime of client credentials JWTs |

`config/dev.json` names each resource server: its audience, the clients whose
roles it sees, an optional flat role claim, and the UMA clients it needs
evaluated. Service keys come from the environment variable named by `keyEnv`.
Any service key can read any user data namespace by subject.

### What Keycloak needs

- A confidential client with a service account holding `view-users`,
  `view-clients` and `view-authorization` on `realm-management`. Nothing more:
  the service never writes to Keycloak.
- A public client for the console, with PKCE and an audience mapper adding
  `IAM_SESSION_AUDIENCE` to its access tokens.

## Before production

- **Signing key.** Whoever holds it can assert any identity to every API.
  There is one key and no rotation.
- **Password grant.** The dev realm enables it on the console client for the
  test suites. Keep it off elsewhere.
- **No operator view.** Nobody but the owner can list or revoke a token.
- **No rate limiting** on any endpoint. `POST /v1/token` relays every
  credential guess to Keycloak unauthenticated.
- **Role-based UMA only.** Adding a script, time, user or negative policy to a
  client listed under `uma` stops token access to that API until it is removed
  or support is added.
- **The service is on the critical path** of every authenticated request. It
  must be replicated, and its database must be available on the token path.
- **Claims travel in a header.** `odh_permissions` rides in the JWT; a
  `DataWriter` permission list is ~3 KB. Keep header size limits in mind.
- **Not covered:** provider credentials, the push API's per-client UMA
  policies, quota enforcement.
