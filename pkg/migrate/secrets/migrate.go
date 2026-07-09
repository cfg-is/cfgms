// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package secrets implements the "secrets" migrator for CFGMS.
//
// The migrator moves all secrets between backends through pkg/secrets/interfaces:
//
//	cfg migrate --provider secrets --from sops --to openbao
//
// Supported backend names: "sops" (flatfile+SOPS), "openbao" (OpenBao KV v2).
// Both directions are supported.
//
// An optional CA relocation sub-step moves an existing file-based CA private key
// into the target SecretStore without writing the key to any new disk location.
// Configuration is read from environment variables:
//
//	CFGMS_SECRETS_SOPS_STORAGE_ROOT   – flatfile root directory (sops backend)
//	CFGMS_SECRETS_OPENBAO_ADDR        – OpenBao address (openbao backend; fallback: OPENBAO_ADDR)
//	CFGMS_SECRETS_OPENBAO_TOKEN       – OpenBao token (openbao backend; fallback: OPENBAO_TOKEN)
//	CFGMS_MIGRATE_CA_STORAGE_PATH     – path holding ca.key/ca.crt (enables CA sub-step)
//	CFGMS_MIGRATE_CA_TENANT_ID        – tenant ID for CA in target store
//	CFGMS_MIGRATE_CA_KEY_PATH         – secret key name for CA cert (default: "ca")
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/migrate"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"

	_ "github.com/cfgis/cfgms/pkg/secrets/providers/openbao"  // register openbao provider
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops"     // register sops provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile" // register flatfile for sops backend
)

const (
	kindSecret = "secret"
	kindCA     = "ca"
)

func init() {
	migrate.Register("secrets", func(from, to string) (migrate.Migrator, error) {
		srcStore, err := openSecretBackend(from)
		if err != nil {
			return nil, fmt.Errorf("secrets migrator: source backend %q: %w", from, err)
		}
		dstStore, err := openSecretBackend(to)
		if err != nil {
			return nil, fmt.Errorf("secrets migrator: target backend %q: %w", to, err)
		}

		caStoragePath := os.Getenv("CFGMS_MIGRATE_CA_STORAGE_PATH")
		caTenantID := os.Getenv("CFGMS_MIGRATE_CA_TENANT_ID")
		caKeyPath := os.Getenv("CFGMS_MIGRATE_CA_KEY_PATH")
		if caKeyPath == "" {
			caKeyPath = "ca"
		}

		return NewSecretsMigrator(srcStore, dstStore, caStoragePath, caTenantID, caKeyPath), nil
	})
}

// openSecretBackend creates a SecretStore for the named backend using environment variables.
func openSecretBackend(name string) (secretsinterfaces.SecretStore, error) {
	switch name {
	case "sops":
		root := os.Getenv("CFGMS_SECRETS_SOPS_STORAGE_ROOT")
		if root == "" {
			return nil, fmt.Errorf("CFGMS_SECRETS_SOPS_STORAGE_ROOT must be set for sops backend")
		}
		return secretsinterfaces.CreateSecretStoreFromConfig("sops", map[string]interface{}{
			"storage_provider": "flatfile",
			"storage_config":   map[string]interface{}{"root": root},
			"cache_enabled":    false,
		})
	case "openbao":
		cfg := map[string]interface{}{}
		if addr := os.Getenv("CFGMS_SECRETS_OPENBAO_ADDR"); addr != "" {
			cfg["address"] = addr
		}
		if token := os.Getenv("CFGMS_SECRETS_OPENBAO_TOKEN"); token != "" {
			cfg["token"] = token
		}
		return secretsinterfaces.CreateSecretStoreFromConfig("openbao", cfg)
	default:
		return nil, fmt.Errorf("unknown secrets backend %q; supported: sops, openbao", name)
	}
}

// SecretsMigrator moves all secrets from src to dst via pkg/secrets/interfaces.
// Values are held in memory only — no intermediate disk files are written.
// An optional CA sub-step (caStoragePath non-empty) relocates a file-based CA
// private key into the target SecretStore without writing the key to any new location.
type SecretsMigrator struct {
	src           secretsinterfaces.SecretStore
	dst           secretsinterfaces.SecretStore
	caStoragePath string
	caTenantID    string
	caKeyPath     string
}

// NewSecretsMigrator returns a SecretsMigrator that copies secrets from src to dst.
// Set caStoragePath, caTenantID, and caKeyPath to enable the CA relocation sub-step;
// leave caStoragePath empty to skip it.
func NewSecretsMigrator(src, dst secretsinterfaces.SecretStore, caStoragePath, caTenantID, caKeyPath string) *SecretsMigrator {
	if src == nil {
		panic("secrets.NewSecretsMigrator: src must not be nil")
	}
	if dst == nil {
		panic("secrets.NewSecretsMigrator: dst must not be nil")
	}
	return &SecretsMigrator{
		src:           src,
		dst:           dst,
		caStoragePath: caStoragePath,
		caTenantID:    caTenantID,
		caKeyPath:     caKeyPath,
	}
}

// Plan exports secrets from the source and returns per-kind counts.
// No writes to the target are performed.
func (m *SecretsMigrator) Plan(ctx context.Context) (migrate.MigrationReport, error) {
	records, err := m.exportSecrets(ctx)
	if err != nil {
		return migrate.MigrationReport{}, fmt.Errorf("secrets plan: %w", err)
	}
	counts := countByKind(records)
	if m.caStoragePath != "" {
		counts[kindCA] = 1
	}
	return migrate.MigrationReport{Counts: counts, Errors: make(map[string]error)}, nil
}

// Run migrates all secrets and (if configured) the file-based CA private key.
// Idempotent: re-running overwrites with identical values using upsert semantics.
func (m *SecretsMigrator) Run(ctx context.Context) (migrate.MigrationReport, error) {
	records, err := m.exportSecrets(ctx)
	if err != nil {
		return migrate.MigrationReport{}, fmt.Errorf("secrets run: export failed: %w", err)
	}
	if err := m.importSecrets(ctx, records); err != nil {
		return migrate.MigrationReport{}, fmt.Errorf("secrets run: import failed: %w", err)
	}

	counts := countByKind(records)
	errs := make(map[string]error)

	if m.caStoragePath != "" {
		sourceKeyFile, err := m.migrateCA(ctx)
		if err != nil {
			return migrate.MigrationReport{Counts: counts, Errors: errs},
				fmt.Errorf("secrets run: CA migration failed: %w", err)
		}
		counts[kindCA] = 1
		// Report the source ca.key path for operator removal — never auto-delete.
		errs["ca_source_key_path"] = fmt.Errorf("residual CA private key requires manual removal: %s", sourceKeyFile)
	}

	return migrate.MigrationReport{Counts: counts, Errors: errs}, nil
}

// exportSecrets lists and fetches all secrets from the source store.
// Values are held in memory only — no temp files are written.
func (m *SecretsMigrator) exportSecrets(ctx context.Context) ([]migrate.Record, error) {
	metas, err := m.src.ListSecrets(ctx, &secretsinterfaces.SecretFilter{})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	if len(metas) == 0 {
		return nil, nil
	}

	keys := make([]string, 0, len(metas))
	for _, meta := range metas {
		if meta.TenantID == "" || meta.Key == "" {
			continue
		}
		keys = append(keys, meta.TenantID+"/"+meta.Key)
	}

	if len(keys) == 0 {
		return nil, nil
	}

	fetched, err := m.src.GetSecrets(ctx, keys)
	if err != nil {
		return nil, fmt.Errorf("get secrets: %w", err)
	}

	records := make([]migrate.Record, 0, len(fetched))
	for fullKey, secret := range fetched {
		data, err := json.Marshal(secret)
		if err != nil {
			return nil, fmt.Errorf("marshal secret %q: %w", fullKey, err)
		}
		records = append(records, migrate.Record{Kind: kindSecret, ID: fullKey, Data: data})
	}
	return records, nil
}

// importSecrets writes secrets to the target store using StoreSecrets (upsert).
// Values are read from Record.Data in memory — no temp files are written.
func (m *SecretsMigrator) importSecrets(ctx context.Context, records []migrate.Record) error {
	batch := make(map[string]*secretsinterfaces.SecretRequest, len(records))
	for i := range records {
		if records[i].Kind != kindSecret {
			continue
		}
		var secret secretsinterfaces.Secret
		if err := json.Unmarshal(records[i].Data, &secret); err != nil {
			return fmt.Errorf("unmarshal secret %q: %w", records[i].ID, err)
		}
		batch[records[i].ID] = &secretsinterfaces.SecretRequest{
			Key:         secret.Key,
			Value:       secret.Value,
			Metadata:    secret.Metadata,
			Tags:        secret.Tags,
			CreatedBy:   secret.CreatedBy,
			TenantID:    secret.TenantID,
			Description: secret.Description,
		}
	}
	if len(batch) == 0 {
		return nil
	}
	return m.dst.StoreSecrets(ctx, batch)
}

// migrateCA loads the CA from disk into memory and stores it in the target
// SecretStore via StoreCAToSecretStore. The private key is never written to any
// new disk location. Returns the source ca.key path for operator cleanup reporting.
func (m *SecretsMigrator) migrateCA(ctx context.Context) (string, error) {
	ca := &cert.CA{}
	if err := ca.LoadCA(m.caStoragePath); err != nil {
		return "", fmt.Errorf("load CA from %q: %w", m.caStoragePath, err)
	}

	if err := ca.StoreCAToSecretStore(ctx, m.dst, m.caTenantID, m.caKeyPath); err != nil {
		return "", fmt.Errorf("store CA to secret store (tenant=%q keyPath=%q): %w",
			m.caTenantID, m.caKeyPath, err)
	}

	return filepath.Join(m.caStoragePath, "ca.key"), nil
}

func countByKind(records []migrate.Record) map[string]int {
	counts := make(map[string]int, 2)
	for _, r := range records {
		counts[r.Kind]++
	}
	return counts
}
