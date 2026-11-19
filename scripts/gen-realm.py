#!/usr/bin/env python3
"""Build the dev realm from a partial export of the real `noi` realm.

Keeps the API clients, their roles and the UMA configuration exactly as
exported, drops everything else, and adds the IAM clients and test users.

    scripts/gen-realm.py path/to/realm-export.json > keycloak/realm-noi-dev.json
"""
import json
import sys

API_CLIENTS = [
    "odh-api-core",
    "odh-mobility-v2",
    "odh-tourism-api",
    "opendatahub-parking-control-tower",
]

CLIENT_FIELDS = [
    "clientId", "name", "description", "enabled", "publicClient", "bearerOnly",
    "standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled",
    "serviceAccountsEnabled", "authorizationServicesEnabled", "fullScopeAllowed",
    "protocol", "protocolMappers", "defaultClientScopes", "authorizationSettings",
]

USERS = {
    "anna": {
        "first": "Anna", "last": "Pichler",
        "roles": {
            "odh-mobility-v2": ["BDP_A22", "BDP_BLC", "ODH_ROLE_PREMIUM"],
            "odh-api-core": ["EventNOIManager", "ArticleNOIManager", "IDM"],
            "opendatahub-parking-control-tower": ["operator", "origin:A22", "origin:STA"],
        },
    },
    "walter": {
        "first": "Walter", "last": "Hofer",
        "roles": {
            "odh-mobility-v2": ["BDP_ADMIN"],
            "odh-api-core": ["DataWriter"],
            "realm-management": ["view-users"],
            "odh-iam": ["iam-admin"],
        },
    },
    "bob": {"first": "Bob", "last": "Gasser", "roles": {}},
}


def strip_ids(node):
    if isinstance(node, dict):
        return {k: strip_ids(v) for k, v in node.items() if k not in ("id", "containerId")}
    if isinstance(node, list):
        return [strip_ids(v) for v in node]
    return node


def main():
    src = json.load(open(sys.argv[1]))
    by_id = {c["clientId"]: c for c in src["clients"]}

    clients = []
    for cid in API_CLIENTS:
        c = {k: by_id[cid][k] for k in CLIENT_FIELDS if k in by_id[cid]}
        c["protocolMappers"] = strip_ids(c.get("protocolMappers", []))
        if not c.get("publicClient") and not c.get("bearerOnly"):
            c["secret"] = f"{cid}-dev-secret"
        c["redirectUris"] = []
        clients.append(c)

    clients.append({
        "clientId": "odh-iam",
        "name": "ODH identity service",
        "enabled": True,
        "publicClient": False,
        "secret": "odh-iam-dev-secret",
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
    })
    clients.append({
        "clientId": "odh-iam-ui",
        "name": "ODH identity console",
        "enabled": True,
        "publicClient": True,
        "standardFlowEnabled": True,
        # Password grant is on for the e2e suite only; keep it off outside dev.
        "directAccessGrantsEnabled": True,
        "redirectUris": ["http://localhost:4010/*"],
        "webOrigins": ["+"],
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": "http://localhost:4010/*",
        },
        "protocolMappers": [{
            "name": "odh-iam audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.custom.audience": "odh-iam",
                "access.token.claim": "true",
                "id.token.claim": "false",
            },
        }],
    })

    users = [
        {
            "username": "service-account-odh-iam",
            "enabled": True,
            "serviceAccountClientId": "odh-iam",
            "clientRoles": {"realm-management": [
                "view-users", "view-clients", "view-authorization",
            ]},
        },
        {
            "username": "service-account-odh-tourism-api",
            "enabled": True,
            "serviceAccountClientId": "odh-tourism-api",
            "clientRoles": {"odh-tourism-api": ["uma_protection"]},
        },
    ]
    for name, u in USERS.items():
        users.append({
            "username": name,
            "enabled": True,
            "emailVerified": True,
            "email": f"{name}@example.com",
            "firstName": u["first"],
            "lastName": u["last"],
            "credentials": [{"type": "password", "value": name, "temporary": False}],
            "clientRoles": u["roles"],
        })

    realm = {
        "realm": "noi",
        "enabled": True,
        "sslRequired": "none",
        "roles": {
            "realm": [],
            "client": {
                **{cid: strip_ids(src["roles"]["client"].get(cid, [])) for cid in API_CLIENTS},
                "odh-iam": [{"name": "iam-admin", "description": "May list and revoke any user's API tokens", "clientRole": True}],
            },
        },
        "clients": clients,
        "users": users,
    }
    json.dump(realm, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
