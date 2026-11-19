# ENGINE builds the image, COMPOSE runs the stack. With rootless podman:
#   systemctl --user start podman.socket
#   export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
#   make up ENGINE=podman
ENGINE  ?= docker
COMPOSE ?= docker compose

.PHONY: image up down test e2e realm

image:
	$(ENGINE) build -t odh-iam:dev .

up: image
	$(COMPOSE) up -d --no-build

down:
	$(COMPOSE) down -v

test:
	go vet ./...
	go test ./...

# Short caches, so the suite does not wait out the normal propagation delay.
# The browser part needs Firefox.
e2e: image
	IAM_CACHE_TTL=1s IAM_RATE_LIMIT_PER_MINUTE=0 $(COMPOSE) up -d --no-build --force-recreate iam demo-api edge
	go test -tags e2e -count=1 ./e2e/...
	python3 e2e/ui_test.py

# Regenerate the dev realm from a partial export of the real one.
realm:
	scripts/gen-realm.py $(EXPORT) > keycloak/realm-noi-dev.json
