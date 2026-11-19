package server

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/noi-techpark/opendatahub-go-sdk/tel/stdhttp"
)

// instrument is the SDK's net/http instrumentation with this service's
// choices: the console files and the health probe get only the panic guard,
// the hook's successful answers log at DEBUG because there is one per API
// request, and a panic is answered in the API's JSON error shape.
func instrument(next http.Handler) http.Handler {
	return stdhttp.Middleware(stdhttp.Options{
		Skip:  func(r *http.Request) bool { return !observed(r.URL.Path) },
		Level: accessLogLevel,
		OnPanic: func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.")
		},
	})(next)
}

func observed(path string) bool {
	return path != "/healthz" && path != "/readyz" &&
		(strings.HasPrefix(path, "/v1/") || strings.HasPrefix(path, "/.well-known/"))
}

func accessLogLevel(r *http.Request, status int) slog.Level {
	if status == http.StatusOK && strings.HasPrefix(r.Pattern, "GET /v1/forward-auth/") {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}
