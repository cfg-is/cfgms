// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package cirunner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// dirScriptRepository is a minimal read-only script.ScriptRepository backed by
// an on-disk directory of VersionedScript YAML files (one <id>.yaml per script).
// It exists so the register scripts are loaded through the real
// script.ScriptRepository / script.VersionedScript contract rather than ad-hoc
// YAML decoding. Only the read methods are implemented; the rest return an
// unsupported error.
type dirScriptRepository struct {
	dir string
}

func newDirScriptRepository(dir string) *dirScriptRepository {
	return &dirScriptRepository{dir: dir}
}

var errReadOnly = fmt.Errorf("dirScriptRepository is read-only")

func (r *dirScriptRepository) Get(id, _ string) (*script.VersionedScript, error) {
	path := filepath.Join(r.dir, id+".yaml")
	data, err := os.ReadFile(path) //#nosec G304 -- test loads scripts from the in-repo template directory
	if err != nil {
		return nil, fmt.Errorf("read script %q: %w", id, err)
	}
	var vs script.VersionedScript
	if err := yaml.Unmarshal(data, &vs); err != nil {
		return nil, fmt.Errorf("parse script %q: %w", id, err)
	}
	return &vs, nil
}

func (r *dirScriptRepository) List(_ *script.ScriptFilter) ([]*script.ScriptMetadata, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, err
	}
	var out []*script.ScriptMetadata
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".yaml")
		vs, err := r.Get(id, "")
		if err != nil {
			return nil, err
		}
		out = append(out, vs.Metadata)
	}
	return out, nil
}

func (r *dirScriptRepository) Create(*script.VersionedScript) error { return errReadOnly }
func (r *dirScriptRepository) Update(*script.VersionedScript) error { return errReadOnly }
func (r *dirScriptRepository) Delete(string, string) error          { return errReadOnly }
func (r *dirScriptRepository) ListVersions(string) ([]*script.Version, error) {
	return nil, errReadOnly
}
func (r *dirScriptRepository) GetLatestVersion(string) (*script.Version, error) {
	return nil, errReadOnly
}
func (r *dirScriptRepository) Rollback(string, string) error { return errReadOnly }

// Compile-time assertion that dirScriptRepository satisfies the contract.
var _ script.ScriptRepository = (*dirScriptRepository)(nil)

// bannedPatterns are the runtime-code-composition patterns forbidden in CFGMS
// scripts (CLAUDE.md "Banned patterns"). Matched case-insensitively, with word
// boundaries on the single-token commands (iex, eval, python -c) so legitimate
// words like "evaluate" or "index" don't false-positive as the guardrail grows.
var bannedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\biex\b`),
	regexp.MustCompile(`(?i)\binvoke-expression\b`),
	regexp.MustCompile(`(?i)-command\s+"`),
	regexp.MustCompile(`(?i)-encodedcommand\b`),
	regexp.MustCompile(`(?i)-executionpolicy\s+bypass\b`),
	regexp.MustCompile(`(?i)\bbash\s+-c\b`),
	regexp.MustCompile(`(?i)\beval\b`),
	regexp.MustCompile(`(?i)\bpython3?\s+-c\b`),
}

// TestRegisterScriptsBannedPatterns loads both register scripts via a
// ScriptRepository backed by the on-disk templates/scripts/cirunner/ directory
// and asserts: (a) both parse as valid VersionedScript; (b) the body contains no
// banned patterns; (c) CFGMS_SECRET_RUNNER_TOKEN is referenced as a secret param
// (env var), never interpolated into a command string.
func TestRegisterScriptsBannedPatterns(t *testing.T) {
	dir := cirunnerScriptsDir(t)
	repo := newDirScriptRepository(dir)

	cases := []struct {
		id       string
		shell    script.ShellType
		platform string
		tokenRef string // the env-var reference form expected in the body
	}{
		{"register-github-runner-linux", script.ShellBash, "linux", "$CFGMS_SECRET_RUNNER_TOKEN"},
		{"register-github-runner-windows", script.ShellPowerShell, "windows", "$env:CFGMS_SECRET_RUNNER_TOKEN"},
	}

	// AC #5: exactly ONE register script per OS in the library.
	metas, err := repo.List(nil)
	require.NoError(t, err)
	assert.Len(t, metas, len(cases), "exactly one register script per OS must live in the library")

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			// (a) parses as a valid VersionedScript
			vs, err := repo.Get(tc.id, "")
			require.NoError(t, err, "must parse as a valid VersionedScript")
			require.NotNil(t, vs.Metadata)
			require.NoError(t, vs.Metadata.Validate(), "metadata must be valid")
			assert.Equal(t, tc.id, vs.Metadata.ID)
			assert.Equal(t, tc.shell, vs.Metadata.Shell)
			assert.Equal(t, []string{tc.platform}, vs.Metadata.Platform)
			require.NotEmpty(t, vs.Content, "script body must not be empty")

			body := vs.Content

			// (b) no banned runtime-code-composition patterns
			for _, banned := range bannedPatterns {
				assert.Falsef(t, banned.MatchString(body),
					"script %s must not contain banned pattern %q", tc.id, banned.String())
			}

			// (c) the registration token is referenced as the secret env var,
			// never a literal value composed into a command string.
			assert.Contains(t, body, "CFGMS_SECRET_RUNNER_TOKEN",
				"token must be referenced via the secret env var")
			assert.Contains(t, body, tc.tokenRef,
				"token must be referenced as an environment variable, not interpolated")

			// RUNNER_TOKEN must be declared as a script parameter (the secret
			// the staging step binds from the secret store).
			assert.True(t, hasParam(vs.Metadata, "RUNNER_TOKEN"),
				"RUNNER_TOKEN must be declared as a script parameter")
		})
	}
}

func hasParam(meta *script.ScriptMetadata, name string) bool {
	for _, p := range meta.Parameters {
		if p.Name == name {
			return true
		}
	}
	return false
}

// cirunnerScriptsDir resolves the in-repo templates/scripts/cirunner directory
// by walking up from the test working directory to the module root (go.mod).
func cirunnerScriptsDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			scriptsDir := filepath.Join(dir, "templates", "scripts", "cirunner")
			info, err := os.Stat(scriptsDir)
			require.NoErrorf(t, err, "expected register-script directory at %s", scriptsDir)
			require.True(t, info.IsDir())
			return scriptsDir
		}
		parent := filepath.Dir(dir)
		require.NotEqualf(t, parent, dir, "could not locate module root (go.mod) from test dir")
		dir = parent
	}
}
