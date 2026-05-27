// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package config provides mount-point validation for git config sources.
package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"

	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

const mountPointValidationTimeout = 10 * time.Second

// MountPointValidator validates that a git config source mount point is reachable
// and well-formed. It is injected into tenant.Manager via WithMountPointValidator.
type MountPointValidator interface {
	// ValidateMountPoint re-runs full URL security validation and tests connectivity.
	// Credentials are fetched from secretStore only — never from info or env vars.
	// The returned error never contains credential material.
	ValidateMountPoint(ctx context.Context, info *ConfigSourceInfo, secretStore secretsiface.SecretStore) error
}

// DefaultMountPointValidator implements MountPointValidator using go-git remote.ListContext().
// It independently re-validates the URL (scheme, SSRF, userinfo) before making
// any outbound connection, so stored metadata cannot bypass the security checks.
type DefaultMountPointValidator struct {
	// insecureSkipTLS disables TLS certificate verification.
	// Production code always uses false; set via WithInsecureSkipTLS in tests only.
	insecureSkipTLS bool
}

// MountPointValidatorOption is a functional option for DefaultMountPointValidator.
type MountPointValidatorOption func(*DefaultMountPointValidator)

// WithInsecureSkipTLS disables TLS certificate verification.
// FOR TESTS ONLY — never use in production.
func WithInsecureSkipTLS() MountPointValidatorOption {
	return func(v *DefaultMountPointValidator) {
		v.insecureSkipTLS = true
	}
}

// NewDefaultMountPointValidator creates a production-ready DefaultMountPointValidator.
func NewDefaultMountPointValidator(opts ...MountPointValidatorOption) *DefaultMountPointValidator {
	v := &DefaultMountPointValidator{}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// ValidateMountPoint validates a git config source in three steps:
//  1. Re-runs full URL security validation (scheme allowlist, RFC 1918 rejection, userinfo rejection)
//     independently of parse-time checks — does not trust stored metadata.
//  2. Applies a 10-second context deadline (caller may supply a shorter one).
//  3. Fetches credentials from secretStore only, then tests connectivity via go-git
//     remote.ListContext() with no git binary required.
//
// Returns nil for non-git sources. Returns an error that never contains credential material.
func (v *DefaultMountPointValidator) ValidateMountPoint(ctx context.Context, info *ConfigSourceInfo, secretStore secretsiface.SecretStore) error {
	if info == nil || info.Type != ConfigSourceTypeGit {
		return nil
	}

	// Step 1: Re-validate URL independently; do not trust stored metadata.
	if err := validateSourceURL(info.URL); err != nil {
		return fmt.Errorf("URL validation failed: %w", err)
	}

	// Step 2: Apply 10-second deadline; caller's deadline wins if it is sooner.
	ctx, cancel := context.WithTimeout(ctx, mountPointValidationTimeout)
	defer cancel()

	// Step 3: Fetch credentials from secretStore — never from info or env vars.
	var auth *githttp.BasicAuth
	if info.CredentialRef != "" && secretStore != nil {
		secret, err := secretStore.GetSecret(ctx, info.CredentialRef)
		if err != nil {
			return fmt.Errorf("failed to fetch credential from secret store: %w", err)
		}
		if secret != nil && secret.Value != "" {
			auth = &githttp.BasicAuth{
				Username: "git", // conventional placeholder for token-based auth
				Password: secret.Value,
			}
		}
	}

	// Step 4: Test connectivity. The returned error never exposes credential bytes.
	if err := v.listRemote(ctx, info.URL, auth); err != nil {
		return sanitizeConnectionError(err, auth)
	}
	return nil
}

// listRemote calls go-git remote.ListContext to probe the remote without cloning.
func (v *DefaultMountPointValidator) listRemote(ctx context.Context, rawURL string, auth *githttp.BasicAuth) error {
	mem := memory.NewStorage()
	rem := git.NewRemote(mem, &gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{rawURL},
	})
	_, err := rem.ListContext(ctx, &git.ListOptions{
		Auth:            auth,
		InsecureSkipTLS: v.insecureSkipTLS,
	})
	if errors.Is(err, gittransport.ErrEmptyRemoteRepository) {
		return nil // reachable but empty — connectivity is confirmed
	}
	return err
}

// sanitizeConnectionError returns an error whose message contains no credential bytes.
// go-git HTTP errors do not normally include Basic-Auth passwords (credentials travel
// in HTTP headers), but this function scrubs the error string defensively.
func sanitizeConnectionError(err error, auth *githttp.BasicAuth) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if auth != nil {
		if auth.Password != "" {
			msg = strings.ReplaceAll(msg, auth.Password, "[REDACTED]")
		}
		if auth.Username != "" && auth.Username != "git" {
			msg = strings.ReplaceAll(msg, auth.Username, "[REDACTED]")
		}
	}
	return fmt.Errorf("mount point connection test failed: %s", msg)
}
