// Package obs starts logging and telemetry the way the Open Data Hub Go
// services do: JSON slog with LOG_LEVEL, OpenTelemetry providers from the
// TELEMETRY_* environment of the SDK's tel module.
package obs

import (
	"context"
	"os"

	"github.com/noi-techpark/opendatahub-go-sdk/tel"
	"github.com/noi-techpark/opendatahub-go-sdk/tel/logger"
)

// Init installs the JSON logger and the telemetry providers. The returned
// function flushes and stops the exporters.
func Init(ctx context.Context, service string) (func(context.Context), error) {
	logger.InitLogging()
	cfg := tel.NewConfigFromEnv()
	if os.Getenv("SERVICE_NAME") == "" {
		cfg.ServiceName = service
	}
	t, err := tel.NewTelemetry(ctx, cfg)
	if err != nil {
		return nil, err
	}
	tel.SetTelemetry(t)
	return t.Shutdown, nil
}
