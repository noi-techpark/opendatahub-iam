package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestObserved(t *testing.T) {
	for path, want := range map[string]bool{
		"/healthz": false, "/readyz": false, "/": false, "/app.js": false, "/ui/config.json": false,
		"/v1/me": true, "/v1/forward-auth/content": true, "/.well-known/jwks.json": true,
	} {
		if observed(path) != want {
			t.Errorf("%s: observed=%v", path, !want)
		}
	}
}

func TestAccessLogLevelQuietsSuccessfulHookAnswers(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/forward-auth/content", nil)
	r.Pattern = "GET /v1/forward-auth/{service}"
	if accessLogLevel(r, http.StatusOK) != slog.LevelDebug {
		t.Error("a 200 from the hook should log at DEBUG")
	}
	if accessLogLevel(r, http.StatusUnauthorized) != slog.LevelInfo {
		t.Error("a refusal from the hook should log at INFO")
	}
	r.Pattern = "GET /v1/me"
	if accessLogLevel(r, http.StatusOK) != slog.LevelInfo {
		t.Error("other routes log at INFO")
	}
}

func TestPanicIsAnsweredInTheAPIErrorShape(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	rec := httptest.NewRecorder()
	instrument(mux).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/boom", nil))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"internal_error"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
