// Package git implements a GitSourceResolver that maps module references of the
// form "publisher/name@version" to git repositories using a module_sources
// config block, fetches the tagged release and returns a payload-carrying
// bundle.Bundle.
//
// # Repository layout
//
// One repository per module, at "<base>/<name>". The repository ROOT at the tag
// is the bundle installation root (module.yaml, bundle.yaml and the binaries
// bundle.yaml names; a multi-platform module carries every platform in that one
// root). The root is read with bundle.ReadInstalledPayload in strict, full mode,
// so a module repository contains only the bundle files (and .git).
//
// # Ref rule
//
// The version in the reference must be an exact semantic version without a "v"
// prefix (bundle.IsExactSemver) and the repository tag must be exactly that
// string. Branches, HEAD, commit ids, "v"-prefixed versions and any other
// string are refused; only tags are ever listed or fetched.
//
// # Transport rules
//
// A source base must be an https or ssh URL (ValidateBase); file://, http://,
// git://, ext:: and scp-style paths are refused. Every git subprocess runs with
// an explicit environment: GIT_ALLOW_PROTOCOL=https:ssh, no prompts, no system
// or user git config, hooks disabled, no submodule recursion, certificate
// verification locked on, and ssh in BatchMode with normal host-key checking.
// Operators supply trust roots and ssh options through GIT_SSL_CAINFO and
// GIT_SSH_COMMAND in the controller's environment, which pass through.
//
// # Trust anchor
//
// The publisher signature, not the tag and not the transport, is the trust
// anchor. The returned bundle's ContentHash is recomputed from the fetched
// bytes (every binary is verified against its digest) and its manifest
// publisher, name and version must equal the request, so bytes that do not
// match what was signed are an error and never a bundle. A moved tag yields
// different bytes and therefore a different hash for the same triple.
package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"

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
	for publisher, src := range sources {
		if err := ValidateBase(src.Base); err != nil {
			return nil, fmt.Errorf("module source for publisher %q: %w", publisher, err)
		}
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

// Resolve fetches the module identified by ref ("publisher/name@version") from
// the configured git source and returns a payload-carrying Bundle.
//
// The clone URL is "<source.Base>/<name>". version must be an exact semver and
// name a tag of the repository. The tag is fetched shallowly into a scratch
// directory that is removed before returning; the Bundle holds the bytes.
// Errors returned to the caller never contain the clone URL or a filesystem path.
func (r *GitSourceResolver) Resolve(ctx context.Context, ref string) (*bundle.Bundle, error) {
	publisher, name, version, err := parseRef(ref)
	if err != nil {
		return nil, err
	}
	if !bundle.IsExactSemver(version) {
		return nil, fmt.Errorf("invalid module ref: version %q is not an exact semantic version (no \"v\" prefix, no branch or commit id)", version)
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

	r.logger.Info("resolving module repository tag",
		"publisher", logging.SanitizeLogValue(publisher),
		"name", logging.SanitizeLogValue(name),
		"version", logging.SanitizeLogValue(version),
		"url", logging.SanitizeLogValue(cloneURL),
	)

	cloneDir, err := os.MkdirTemp(r.cloneRoot, "clone-*")
	if err != nil {
		return nil, errors.New("create scratch directory for module fetch failed")
	}
	defer func() { _ = os.RemoveAll(cloneDir) }()

	if err := r.fetchTag(ctx, cloneURL, version, cloneDir); err != nil {
		return nil, err
	}

	b, err := bundle.ReadInstalledPayload(cloneDir, bundle.ReadOptions{IgnoreNames: []string{".git"}})
	if err != nil {
		r.logger.Warn("module repository is not a valid bundle",
			"publisher", logging.SanitizeLogValue(publisher),
			"name", logging.SanitizeLogValue(name),
			"version", logging.SanitizeLogValue(version),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		return nil, scrub(fmt.Sprintf("read module bundle for %s/%s@%s", publisher, name, version), err, cloneDir, cloneURL)
	}
	if err := bindIdentity(b, publisher, name, version); err != nil {
		return nil, err
	}
	return b, nil
}

// bindIdentity requires the bundle's manifest and signatures to name exactly the
// publisher, name and version that were requested.
func bindIdentity(b *bundle.Bundle, publisher, name, version string) error {
	if b.Manifest == nil {
		return errors.New("module manifest missing")
	}
	if b.Manifest.Publisher != publisher {
		return fmt.Errorf("module manifest publisher %q does not match requested publisher %q", b.Manifest.Publisher, publisher)
	}
	if b.Manifest.Name != name {
		return fmt.Errorf("module manifest name %q does not match requested name %q", b.Manifest.Name, name)
	}
	if b.Manifest.Version != version {
		return fmt.Errorf("module manifest version %q does not match requested version %q", b.Manifest.Version, version)
	}
	for _, sig := range b.Signatures {
		if sig.Publisher != b.Manifest.Publisher {
			return fmt.Errorf("module signature publisher %q does not match manifest publisher %q", sig.Publisher, b.Manifest.Publisher)
		}
	}
	return nil
}

// scrubbedError carries a message with the clone URL and scratch path removed
// while keeping the original error reachable through errors.Is / errors.As.
type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

func scrub(prefix string, err error, secrets ...string) error {
	text := err.Error()
	for _, s := range secrets {
		if s != "" {
			text = strings.ReplaceAll(text, s, "<redacted>")
		}
	}
	return &scrubbedError{msg: prefix + ": " + text, err: err}
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
	if err := ValidateBase(base); err != nil {
		return "", err
	}
	// Strip trailing slash from base before joining.
	return strings.TrimRight(base, "/") + "/" + name, nil
}

// ValidateBase reports whether base is an acceptable module source base URL: an
// absolute https or ssh URL with a host, no password, no query or fragment, and
// no whitespace or control characters. file://, http://, git://, ext:: and
// scp-style "host:path" bases are refused. A user name (ssh://git@host/...) is
// allowed for ssh only; credentials are never part of the URL. It is the single
// rule applied by New and by controller config validation.
func ValidateBase(base string) error {
	if base == "" {
		return errors.New("source base URL is empty")
	}
	for _, c := range base {
		if unicode.IsSpace(c) || unicode.IsControl(c) || c == '\\' {
			return errors.New("source base URL contains whitespace, control or backslash characters")
		}
	}
	if !strings.Contains(base, "://") {
		return errors.New("source base URL must be an absolute https:// or ssh:// URL")
	}
	u, err := url.Parse(base)
	if err != nil {
		return errors.New("source base URL is not a valid URL")
	}
	if u.Scheme != "https" && u.Scheme != "ssh" {
		return fmt.Errorf("source base URL scheme %q is not allowed (https or ssh only)", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return errors.New("source base URL has no host")
	}
	if strings.HasPrefix(u.Hostname(), "-") || strings.Contains(u.Host, "%") {
		return errors.New("source base URL host is invalid")
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword || u.Scheme != "ssh" || u.User.Username() == "" || strings.HasPrefix(u.User.Username(), "-") {
			return errors.New("source base URL must not carry credentials")
		}
	}
	if u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(base, "?#") {
		return errors.New("source base URL must not carry a query or fragment")
	}
	return nil
}

// gitEnv returns the explicit environment every git subprocess runs with. Only
// GIT_SSL_CAINFO and GIT_SSH_COMMAND are passed through from the controller's
// environment (operator trust roots / ssh options); every other GIT_* variable
// is dropped. certificate verification is never disabled.
func gitEnv(environ []string) []string {
	var env []string
	var caInfo, sshCmd string
	for _, kv := range environ {
		switch {
		case strings.HasPrefix(kv, "GIT_SSL_CAINFO="):
			caInfo = strings.TrimPrefix(kv, "GIT_SSL_CAINFO=")
		case strings.HasPrefix(kv, "GIT_SSH_COMMAND="):
			sshCmd = strings.TrimPrefix(kv, "GIT_SSH_COMMAND=")
		case strings.HasPrefix(kv, "GIT_"):
		default:
			env = append(env, kv)
		}
	}
	// BatchMode never prompts; StrictHostKeyChecking is left to ssh's default
	// (or the operator's own command) and is never set here.
	if sshCmd == "" {
		sshCmd = "ssh"
	}
	sshCmd += " -o BatchMode=yes"
	env = append(env,
		"GIT_ALLOW_PROTOCOL=https:ssh",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_SSH_COMMAND="+sshCmd,
	)
	if caInfo != "" {
		env = append(env, "GIT_SSL_CAINFO="+caInfo)
	}
	return env
}

// gitConfigArgs returns the "-c" settings placed before every git subcommand:
// certificate verification locked on, hooks pointed at an empty directory, no
// submodule recursion, no filters or line-ending conversion, no protocol other
// than https and ssh.
func gitConfigArgs(hooksDir string) []string {
	return []string{
		"-c", "http.sslVerify=true",
		"-c", "core.hooksPath=" + hooksDir,
		"-c", "submodule.recurse=false",
		"-c", "core.autocrlf=false",
		"-c", "core.fsmonitor=false",
		"-c", "core.symlinks=true",
		"-c", "protocol.allow=never",
		"-c", "protocol.https.allow=always",
		"-c", "protocol.ssh.allow=always",
		"-c", "transfer.fsckObjects=true",
	}
}

// runGit runs a git subcommand with the locked-down environment and arguments.
// Output is returned for logging only; callers must never put it, the URL or a
// path in an error returned to an API caller.
func (r *GitSourceResolver) runGit(ctx context.Context, dir string, args ...string) (string, error) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		return "", errors.New("git binary not found in PATH")
	}
	hooksDir := filepath.Join(r.cloneRoot, ".empty-hooks")
	if err := os.MkdirAll(hooksDir, 0750); err != nil {
		return "", errors.New("create empty hooks directory failed")
	}
	full := append(gitConfigArgs(hooksDir), args...)
	// #nosec G204 -- gitBin is resolved via exec.LookPath; every caller passes
	// URL and ref after "--" and the ref is a validated exact semver.
	cmd := exec.CommandContext(ctx, gitBin, full...)
	cmd.Dir = dir
	cmd.Env = gitEnv(os.Environ())
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return out.String(), ctxErr
		}
		return out.String(), err
	}
	return out.String(), nil
}

// fetchTag shallow-fetches exactly the tag "version" from cloneURL into destDir
// and checks it out. Errors returned name neither the URL nor destDir.
func (r *GitSourceResolver) fetchTag(ctx context.Context, cloneURL, version, destDir string) error {
	tagRef, err := r.resolveRemoteRef(ctx, cloneURL, version)
	if err != nil {
		return err
	}
	steps := [][]string{
		{"init", "--quiet", "--template=", "."},
		{"fetch", "--quiet", "--depth", "1", "--no-tags", "--no-recurse-submodules", "--", cloneURL, "+" + tagRef + ":" + tagRef},
		{"checkout", "--quiet", "--detach", tagRef},
	}
	for _, args := range steps {
		if out, err := r.runGit(ctx, destDir, args...); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			r.logger.Warn("git operation failed",
				"op", logging.SanitizeLogValue(args[0]),
				"error", logging.SanitizeLogValue(err.Error()),
				"output", logging.SanitizeLogValue(out),
			)
			return fmt.Errorf("git %s of module tag %q failed", args[0], version)
		}
	}
	return nil
}

// resolveRemoteRef confirms that the exact tag "version" exists on cloneURL and
// returns its full ref name. Only tags are listed ("--tags"); a branch, HEAD or
// commit id of the same spelling is never matched.
func (r *GitSourceResolver) resolveRemoteRef(ctx context.Context, cloneURL, version string) (string, error) {
	want := "refs/tags/" + version
	// "--" prevents cloneURL or the pattern from being interpreted as flags.
	out, err := r.runGit(ctx, r.cloneRoot, "ls-remote", "--tags", "--", cloneURL, want)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		r.logger.Warn("git ls-remote failed",
			"error", logging.SanitizeLogValue(err.Error()),
			"output", logging.SanitizeLogValue(out),
		)
		return "", errors.New("module source is unreachable or refused the request")
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && (fields[1] == want || fields[1] == want+"^{}") {
			return want, nil
		}
	}
	return "", fmt.Errorf("tag %q not found on module source", version)
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
