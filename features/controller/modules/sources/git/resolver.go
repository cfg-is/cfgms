// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Package git implements a GitSourceResolver that maps module references of the
// form "publisher/name@version" to git clone URLs using a module_sources config
// block, clones the repository, and returns a parsed Bundle.
package git

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// SourceConfig describes a module source repository namespace.
type SourceConfig struct {
	// Type is always "git" for this resolver.
	Type string `yaml:"type"`
	// Base is the base URL; the module name is appended as a path segment.
	// e.g. "https://github.com/cfgis" → clone URL "https://github.com/cfgis/<name>"
	Base string `yaml:"base"`
}

// GitSourceResolver maps publisher namespaces to git repositories using a
// module_sources config block and resolves module references to bundles.
type GitSourceResolver struct {
	// sources maps publisher names to their SourceConfig.
	sources map[string]SourceConfig
	// cloneRoot is the parent directory for cloned repositories.
	cloneRoot string
	// logger is used for structured log output.
	logger logging.Logger
}

// New creates a GitSourceResolver.
// sources maps publisher name → SourceConfig.
// cloneRoot is the directory under which cloned repos are placed; it is created
// if it does not exist.
func New(sources map[string]SourceConfig, cloneRoot string, logger logging.Logger) (*GitSourceResolver, error) {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	if err := os.MkdirAll(cloneRoot, 0750); err != nil {
		return nil, fmt.Errorf("create clone root: %w", err)
	}
	return &GitSourceResolver{
		sources:   sources,
		cloneRoot: cloneRoot,
		logger:    logger,
	}, nil
}

// Resolve fetches the module identified by ref ("publisher/name@version"), clones
// it from the configured git source, and returns a parsed Bundle.
//
// The clone URL is constructed as "<source.Base>/<name>" (no trailing slash).
// Shallow clone (--depth 1) is used to minimise network and disk usage.
func (r *GitSourceResolver) Resolve(ctx context.Context, ref string) (*bundle.Bundle, error) {
	publisher, name, version, err := parseRef(ref)
	if err != nil {
		return nil, err
	}

	src, ok := r.sources[publisher]
	if !ok {
		return nil, fmt.Errorf("no module source configured for publisher %q", publisher)
	}
	if src.Type != "git" {
		return nil, fmt.Errorf("unsupported source type %q for publisher %q", src.Type, publisher)
	}

	cloneURL, err := buildCloneURL(src.Base, name)
	if err != nil {
		return nil, err
	}

	cloneDir, err := r.cloneRepo(ctx, publisher, name, version, cloneURL)
	if err != nil {
		return nil, fmt.Errorf("clone %s: %w", logging.SanitizeLogValue(cloneURL), err)
	}

	return parseBundleFromDir(cloneDir, version)
}

// ResolveURL returns the git clone URL for the given ref without cloning.
// Useful for diagnostics and testing URL mapping without network access.
func (r *GitSourceResolver) ResolveURL(ref string) (string, error) {
	publisher, name, _, err := parseRef(ref)
	if err != nil {
		return "", err
	}
	src, ok := r.sources[publisher]
	if !ok {
		return "", fmt.Errorf("no module source configured for publisher %q", publisher)
	}
	return buildCloneURL(src.Base, name)
}

// parseRef parses "publisher/name@version" into its components.
func parseRef(ref string) (publisher, name, version string, err error) {
	atIdx := strings.LastIndex(ref, "@")
	if atIdx < 0 {
		return "", "", "", fmt.Errorf("invalid module ref %q: missing @version (expected publisher/name@version)", ref)
	}
	version = ref[atIdx+1:]
	namespacedName := ref[:atIdx]

	slashIdx := strings.Index(namespacedName, "/")
	if slashIdx < 0 {
		return "", "", "", fmt.Errorf("invalid module ref %q: missing publisher/ prefix (expected publisher/name@version)", ref)
	}
	publisher = namespacedName[:slashIdx]
	name = namespacedName[slashIdx+1:]

	if err := validatePathComponent(publisher); err != nil {
		return "", "", "", fmt.Errorf("publisher: %w", err)
	}
	if err := validatePathComponent(name); err != nil {
		return "", "", "", fmt.Errorf("name: %w", err)
	}
	if err := validatePathComponent(version); err != nil {
		return "", "", "", fmt.Errorf("version: %w", err)
	}
	return publisher, name, version, nil
}

// buildCloneURL constructs the git clone URL from base and name.
func buildCloneURL(base, name string) (string, error) {
	if base == "" {
		return "", errors.New("source base URL is empty")
	}
	// Strip trailing slash from base before joining.
	return strings.TrimRight(base, "/") + "/" + name, nil
}

// cloneRepo clones cloneURL to a subdirectory of cloneRoot.
// Idempotent: if the destination already exists (has a .git dir), it is reused.
func (r *GitSourceResolver) cloneRepo(ctx context.Context, publisher, name, version, cloneURL string) (string, error) {
	// Derive a stable local directory name from the content-addressed tuple.
	dirName := publisher + "-" + name + "-" + version
	cloneDir := filepath.Join(r.cloneRoot, dirName)

	// Idempotent: reuse existing clone.
	if _, err := os.Stat(filepath.Join(cloneDir, ".git")); err == nil {
		return cloneDir, nil
	}

	gitBin, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("git binary not found in PATH: %w", err)
	}

	r.logger.Info("cloning module repository",
		"publisher", logging.SanitizeLogValue(publisher),
		"name", logging.SanitizeLogValue(name),
		"version", logging.SanitizeLogValue(version),
		"url", logging.SanitizeLogValue(cloneURL),
	)

	// "--" prevents git from interpreting a URL starting with "-" as a flag.
	// #nosec G204 - gitBin is resolved via exec.LookPath; cloneURL is separated by "--"
	cmd := exec.CommandContext(ctx, gitBin, "clone", "--depth", "1", "--", cloneURL, cloneDir)
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		return "", fmt.Errorf("git clone failed: %w (output: %s)", runErr, string(out))
	}

	return cloneDir, nil
}

// parseBundleFromDir reads module.yaml, binary files, and signature files from cloneDir
// and assembles a Bundle with a computed content hash.
func parseBundleFromDir(cloneDir, version string) (*bundle.Bundle, error) {
	// Read module.yaml.
	metaPath := filepath.Join(cloneDir, "module.yaml")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("read module.yaml: %w", err)
	}

	var meta modules.ModuleMetadata
	if err := yaml.Unmarshal(metaData, &meta); err != nil {
		return nil, fmt.Errorf("parse module.yaml: %w", err)
	}

	// Discover binary files under binaries/.
	binDir := filepath.Join(cloneDir, "binaries")
	binaries := make(map[string]string)
	binContent := make(map[string][]byte)

	if entries, readErr := os.ReadDir(binDir); readErr == nil {
		for _, e := range entries {
			entryPath := filepath.Join(binDir, e.Name())
			// Use Lstat so symlinks are never followed: only regular files are valid
			// binary entries. A malicious publisher could commit a symlink whose target
			// points outside the clone root; rejecting non-regular files prevents that.
			fi, statErr := os.Lstat(entryPath)
			if statErr != nil {
				continue
			}
			if !fi.Mode().IsRegular() {
				continue
			}
			relPath := filepath.Join("binaries", e.Name())
			binaries[e.Name()] = relPath
			content, readErr := os.ReadFile(entryPath)
			if readErr != nil {
				return nil, fmt.Errorf("read binary %q: %w", e.Name(), readErr)
			}
			binContent[e.Name()] = content
		}
	}

	// Compute content hash from binary content and manifest YAML.
	contentHash, err := bundle.ComputeContentHash(binContent, metaData)
	if err != nil {
		return nil, fmt.Errorf("compute content hash: %w", err)
	}

	// Read signature files from signatures/.
	var sigs []bundle.BundleSignature
	sigDir := filepath.Join(cloneDir, "signatures")
	if entries, readErr := os.ReadDir(sigDir); readErr == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			sigData, readErr := os.ReadFile(filepath.Join(sigDir, e.Name()))
			if readErr != nil {
				continue
			}
			var sig bundle.BundleSignature
			if yaml.Unmarshal(sigData, &sig) == nil {
				sigs = append(sigs, sig)
			}
		}
	}

	return &bundle.Bundle{
		Manifest:    &meta,
		Binaries:    binaries,
		Signatures:  sigs,
		ContentHash: contentHash,
	}, nil
}

// validatePathComponent rejects empty strings and path traversal sequences.
func validatePathComponent(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	if strings.Contains(s, "..") || strings.ContainsRune(s, '/') || strings.ContainsRune(s, '\\') {
		return fmt.Errorf("must not contain path separators or dot sequences: %q", s)
	}
	return nil
}
