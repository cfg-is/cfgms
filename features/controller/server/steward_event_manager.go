package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"

	// New builds the steward-event manager itself, so the logging providers it
	// can select must be registered by this package, not only by cmd/controller.
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/timescale"
)

// stewardEventFilePrefix keeps steward-event files distinct from the
// controller's own log files when both use the file provider.
const stewardEventFilePrefix = "steward-events"

// LogProvider determines the logging provider from configuration.
func LogProvider(cfg *config.Config) string {
	if cfg.Logging != nil && cfg.Logging.Provider != "" {
		return cfg.Logging.Provider
	}
	return "file"
}

// LogProviderConfig creates provider-specific configuration.
// For the timescale provider all 6 connection fields are read exclusively from
// the SecretStore under the "controller/logging/timescale/<field>" keys.
// A missing secret is a hard startup error — there is no env var fallback.
func LogProviderConfig(cfg *config.Config, store secretsif.SecretStore) (map[string]interface{}, error) {
	if cfg.Logging != nil && cfg.Logging.Config != nil && len(cfg.Logging.Config) > 0 {
		return cfg.Logging.Config, nil
	}

	provider := LogProvider(cfg)

	switch provider {
	case "timescale":
		if store == nil {
			return nil, fmt.Errorf("controller logging: SecretStore is required for TimescaleDB credentials")
		}
		ctx := context.Background()
		// field → leaf key under "controller/" tenant
		// key format: controller/logging-timescale-<field>
		// (SOPS store requires tenant/leaf where leaf must not contain '/')
		fields := []string{"password", "host", "port", "database", "username", "ssl_mode"}
		result := make(map[string]interface{}, len(fields))
		for _, field := range fields {
			leaf := "logging-timescale-" + strings.ReplaceAll(field, "_", "-")
			key := "controller/" + leaf
			secret, err := store.GetSecret(ctx, key)
			if err != nil {
				if errors.Is(err, secretsif.ErrSecretNotFound) {
					return nil, fmt.Errorf("timescale %s: secret '%s' not found in store; "+
						"pre-store via the secrets CLI before starting the controller", field, key)
				}
				return nil, fmt.Errorf("timescale %s: failed to retrieve secret '%s': %w", field, key, err)
			}
			result[field] = secret.Value
		}
		return result, nil

	default:
		return map[string]interface{}{
			"directory":        "/var/log/cfgms",
			"max_file_size":    int64(100 * 1024 * 1024),
			"max_files":        10,
			"compress_rotated": true,
		}, nil
	}
}

// newStewardEventManager builds the dedicated LoggingManager that ingests
// steward log entries (Issue #4857). It follows the controller's logging
// configuration (provider and provider settings). With the file provider and no
// explicit provider settings, entries are written under the controller data
// root rather than the system log directory, with a distinct file prefix.
// Construction failure is returned: the controller must never start with a nil
// steward-event manager, which silently discards every steward log entry.
func newStewardEventManager(cfg *config.Config, store secretsif.SecretStore) (*logging.LoggingManager, error) {
	provider := LogProvider(cfg)
	explicit := cfg.Logging != nil && len(cfg.Logging.Config) > 0

	var providerCfg map[string]interface{}
	if provider == "file" && !explicit {
		dir := filepath.Join(resolveDNADataRoot(cfg), "steward-events")
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create steward event log directory: %w", err)
		}
		providerCfg = map[string]interface{}{
			"directory":        dir,
			"file_prefix":      stewardEventFilePrefix,
			"max_file_size":    int64(100 * 1024 * 1024),
			"max_files":        10,
			"compress_rotated": true,
		}
	} else {
		base, err := LogProviderConfig(cfg, store)
		if err != nil {
			return nil, fmt.Errorf("failed to build steward event log provider config: %w", err)
		}
		providerCfg = make(map[string]interface{}, len(base)+1)
		for k, v := range base {
			providerCfg[k] = v
		}
		if provider == "file" {
			if _, ok := providerCfg["file_prefix"]; !ok {
				providerCfg["file_prefix"] = stewardEventFilePrefix
			}
		}
	}

	mgr, err := logging.NewLoggingManager(&logging.LoggingConfig{
		Provider:          provider,
		Level:             strings.ToUpper(cfg.LogLevel),
		ServiceName:       "controller",
		Component:         "steward-events",
		TenantIsolation:   true,
		EnableCorrelation: true,
		EnableTracing:     true,
		AsyncWrites:       true,
		BatchSize:         100,
		FlushInterval:     time.Second,
		RetentionDays:     90,
		Config:            providerCfg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create steward event logging manager: %w", err)
	}
	return mgr, nil
}

// closeStewardEventManager flushes then closes the manager so buffered entries
// are not lost on shutdown.
func closeStewardEventManager(mgr *logging.LoggingManager) error {
	if mgr == nil {
		return nil
	}
	flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	flushErr := mgr.Flush(flushCtx)
	return errors.Join(flushErr, mgr.Close())
}
