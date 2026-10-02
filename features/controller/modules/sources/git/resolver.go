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

// cloneRepo resolves version (a tag, branch or commit SHA) to an exact commit on
// cloneURL, checks that commit out, and returns the directory it was checked out
// into. The directory name is keyed by the resolved commit — not just the
// requested version string — so that two requests for the same version can never
// share a cache entry unless they truly resolved to the same commit, and a
// mis-keyed first resolution cannot poison later lookups for the same version.
//
// Idempotent: if a directory for the resolved commit already exists (has a .git
// dir), it is reused without a network round-trip beyond the ref resolution.
func (r *GitSourceResolver) cloneRepo(ctx context.Context, publisher, name, version, cloneURL string) (string, error) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("git binary not found in PATH: %w", err)
	}

	r.logger.Info("resolving module repository ref",
		"publisher", logging.SanitizeLogValue(publisher),
		"name", logging.SanitizeLogValue(name),
		"version", logging.SanitizeLogValue(version),
		"url", logging.SanitizeLogValue(cloneURL),
	)

	// version is usually a tag or branch name, which ls-remote can resolve to a
	// commit without fetching any objects. This lets the idempotent-reuse check
	// below run before any clone/fetch happens.
	commit, lsErr := resolveRemoteRef(ctx, gitBin, cloneURL, version)
	if lsErr != nil {
		return r.cloneUnresolvedRef(ctx, gitBin, publisher, name, version, cloneURL, lsErr)
	}

	cloneDir := filepath.Join(r.cloneRoot, cacheDirName(publisher, name, version, commit))
	if _, statErr := os.Stat(filepath.Join(cloneDir, ".git")); statErr == nil {
		return cloneDir, nil
	}
	if err := shallowFetchInto(ctx, gitBin, cloneURL, version, cloneDir); err != nil {
		return "", fmt.Errorf("fetch ref %q: %w", version, err)
	}
	return cloneDir, nil
}

// cloneUnresolvedRef handles a version that ls-remote could not resolve as a tag
// or branch (it may be a raw commit SHA, or it may simply not exist). It stages a
// full fetch-then-checkout in a scratch directory so the resolved commit — and
// therefore the final cache key — is only known once the checkout has actually
// succeeded. It never falls back to the remote's default branch: checkout always
// names the exact requested version, so an unresolvable ref fails closed.
func (r *GitSourceResolver) cloneUnresolvedRef(ctx context.Context, gitBin, publisher, name, version, cloneURL string, lsErr error) (string, error) {
	stagingDir, err := os.MkdirTemp(r.cloneRoot, ".staging-*")
	if err != nil {
		return "", fmt.Errorf("create staging dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(stagingDir) }()

	commit, err := fullFetchCheckout(ctx, gitBin, cloneURL, version, stagingDir)
	if err != nil {
		return "", fmt.Errorf("resolve ref %q: %w (ls-remote: %s)", version, err, lsErr)
	}

	cloneDir := filepath.Join(r.cloneRoot, cacheDirName(publisher, name, version, commit))
	if _, statErr := os.Stat(filepath.Join(cloneDir, ".git")); statErr == nil {
		return cloneDir, nil
	}
	if err := os.Rename(stagingDir, cloneDir); err != nil {
		return "", fmt.Errorf("move resolved clone into place: %w", err)
	}
	return cloneDir, nil
}

// cacheDirName derives the local cache directory name from the resolved
// content-addressed tuple, including a short prefix of the resolved commit so
// that different commits for the same requested version never collide.
func cacheDirName(publisher, name, version, commit string) string {
	short := commit
	if len(short) > 12 {
		short = short[:12]
	}
	return publisher + "-" + name + "-" + version + "-" + short
}

// resolveRemoteRef resolves ref (a tag or branch name) to a commit SHA on
// cloneURL using "git ls-remote", without fetching any objects. Annotated tags
// are peeled to the commit they point at. Returns an error if ref does not
// match any tag or branch on the remote.
func resolveRemoteRef(ctx context.Context, gitBin, cloneURL, ref string) (string, error) {
	// "--" prevents cloneURL or ref from being interpreted as flags.
	// #nosec G204 -- gitBin is resolved via exec.LookPath; cloneURL/ref follow "--"
	cmd := exec.CommandContext(ctx, gitBin, "ls-remote", "--tags", "--heads", "--", cloneURL, ref)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ls-remote failed: %w", err)
	}

	var plain, peeled string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		sha, refName := fields[0], fields[1]
		if strings.HasSuffix(refName, "^{}") {
			peeled = sha
		} else if plain == "" {
			plain = sha
		}
	}
	if peeled != "" {
		return peeled, nil
	}
	if plain != "" {
		return plain, nil
	}
	return "", fmt.Errorf("ref %q not found on remote", ref)
}

// shallowFetchInto initializes an empty repository at destDir and shallow-fetches
// exactly ref from cloneURL, then checks it out. destDir is removed on failure so
// a failed fetch never leaves a directory behind under a cache-key name.
func shallowFetchInto(ctx context.Context, gitBin, cloneURL, ref, destDir string) error {
	if err := os.MkdirAll(destDir, 0750); err != nil {
		return fmt.Errorf("create clone dir: %w", err)
	}
	// #nosec G204 -- gitBin is resolved via exec.LookPath; destDir is controller-generated.
	if out, err := exec.CommandContext(ctx, gitBin, "init", "--quiet", destDir).CombinedOutput(); err != nil {
		_ = os.RemoveAll(destDir)
		return fmt.Errorf("git init failed: %w (output: %s)", err, string(out))
	}
	// "--" prevents cloneURL or ref from being interpreted as flags.
	// #nosec G204 -- gitBin is resolved via exec.LookPath; cloneURL/ref follow "--"
	fetchCmd := exec.CommandContext(ctx, gitBin, "-C", destDir, "fetch", "--depth", "1", "--", cloneURL, ref)
	if out, err := fetchCmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(destDir)
		return fmt.Errorf("git fetch failed: %w (output: %s)", err, string(out))
	}
	// #nosec G204 -- gitBin is resolved via exec.LookPath; FETCH_HEAD is a fixed literal.
	if out, err := exec.CommandContext(ctx, gitBin, "-C", destDir, "checkout", "--quiet", "FETCH_HEAD").CombinedOutput(); err != nil {
		_ = os.RemoveAll(destDir)
		return fmt.Errorf("git checkout failed: %w (output: %s)", err, string(out))
	}
	return nil
}

// fullFetchCheckout initializes an empty repository at destDir, fetches ref from
// cloneURL (falling back to fetching the full tag/branch namespace if the remote
// refuses to advertise/fetch the ref directly — e.g. a raw commit SHA on a server
// without uploadpack.allowReachableSHA1InWant), checks out exactly ref, and
// returns the resulting HEAD commit SHA. It never checks out anything other than
// the requested ref, so an unresolvable ref fails closed rather than falling
// back to the remote's default branch.
func fullFetchCheckout(ctx context.Context, gitBin, cloneURL, ref, destDir string) (string, error) {
	// #nosec G204 -- gitBin is resolved via exec.LookPath; destDir is controller-generated.
	if out, err := exec.CommandContext(ctx, gitBin, "init", "--quiet", destDir).CombinedOutput(); err != nil {
		return "", fmt.Errorf("git init failed: %w (output: %s)", err, string(out))
	}

	// "--" prevents cloneURL or ref from being interpreted as flags.
	// #nosec G204 -- gitBin is resolved via exec.LookPath; cloneURL/ref follow "--"
	fetchCmd := exec.CommandContext(ctx, gitBin, "-C", destDir, "fetch", "--", cloneURL, ref)
	out, fetchErr := fetchCmd.CombinedOutput()
	if fetchErr != nil {
		// #nosec G204 -- gitBin is resolved via exec.LookPath; cloneURL follows "--"
		fetchAllCmd := exec.CommandContext(ctx, gitBin, "-C", destDir, "fetch", "--",
			cloneURL, "+refs/heads/*:refs/remotes/origin/*", "+refs/tags/*:refs/tags/*")
		if out2, err2 := fetchAllCmd.CombinedOutput(); err2 != nil {
			return "", fmt.Errorf("git fetch failed for ref %q: %w (output: %s / %s)", ref, fetchErr, string(out), string(out2))
		}
	}

	// #nosec G204 -- gitBin is resolved via exec.LookPath; ref is a validated path component.
	if out, err := exec.CommandContext(ctx, gitBin, "-C", destDir, "checkout", "--quiet", ref).CombinedOutput(); err != nil {
		return "", fmt.Errorf("git checkout failed for ref %q: %w (output: %s)", ref, err, string(out))
	}

	// #nosec G204 -- gitBin is resolved via exec.LookPath; destDir is controller-generated; "HEAD" is a fixed literal.
	revParseOut, err := exec.CommandContext(ctx, gitBin, "-C", destDir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("rev-parse HEAD failed: %w", err)
	}
	return strings.TrimSpace(string(revParseOut)), nil
}

// parseBundleFromDir reads module.yaml, binary files, and signature files from cloneDir
// and assembles a Bundle with a computed content hash.
func parseBundleFromDir(cloneDir, version string) (*bundle.Bundle, error) {
	// Read module.yaml.
	metaPath := filepath.Join(cloneDir, "module.yaml")
	// #nosec G304 -- cloneDir is a controller-created temporary Git checkout
	// and module.yaml is a fixed filename beneath it.
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
			// #nosec G304 -- entryPath comes from ReadDir of cloneDir/binaries
			// and was lstat-verified as a regular, non-symlink file above.
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
			// #nosec G304 -- e.Name comes from ReadDir of cloneDir/signatures
			// and is restricted to non-directory .yaml entries.
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
	// publisher, name and version are all passed as literal arguments to git
	// subcommands (ls-remote, fetch, checkout). A leading "-" would let a
	// crafted ref be interpreted as a git flag rather than a ref name.
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("must not start with '-': %q", s)
	}
	return nil
}
