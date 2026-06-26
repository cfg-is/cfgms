// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package github_runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// stateFileName is the module's on-disk drift marker, written under the runner
// work directory. It records the converged agent version, label set, and service
// name so Get/Test are deterministic and network-free.
const stateFileName = ".cfgms-github-runner.json"

// sha256HexPattern matches a lowercase or uppercase 64-character hex SHA-256.
var sha256HexPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// serviceNamePattern restricts the service name to characters safe to pass to
// systemctl / sc.exe without shell quoting; it must start alphanumeric to
// prevent flag injection. GitHub runner units look like
// "actions.runner.<owner>-<repo>.<name>.service".
var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,254}$`)

// labelPattern restricts runner labels to GitHub's allowed label characters.
var labelPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// RunnerConfig is the desired (and, when returned by Get, observed) state of a
// self-hosted runner. There is intentionally NO registration-token field: the
// module never registers the runner, so a token never appears in its schema or
// config surface.
type RunnerConfig struct {
	// Version is the pinned runner agent version (e.g. "2.319.1").
	Version string `yaml:"version"`
	// AgentURL is the download URL for the agent archive at Version.
	AgentURL string `yaml:"agent_url"`
	// AgentSHA256 is the operator-pinned expected SHA-256 of the archive (hex).
	// Verification uses this value directly — there is no network hash lookup.
	AgentSHA256 string `yaml:"agent_sha256"`
	// Labels is the desired runner label set.
	Labels []string `yaml:"labels,omitempty"`
	// WorkDir is the absolute install directory; it is also the resource ID.
	WorkDir string `yaml:"work_dir"`
	// ServiceName is the OS service name of the runner service.
	ServiceName string `yaml:"service_name"`

	// Observed-only fields, populated by Get (never read from operator config).
	Installed      bool `yaml:"installed,omitempty"`
	ServiceRunning bool `yaml:"service_running,omitempty"`
	ServiceEnabled bool `yaml:"service_enabled,omitempty"`
}

// AsMap returns the drift-comparable fields. agent_url/agent_sha256 are inputs
// that define HOW to converge, not observable drift dimensions, so they are
// omitted from the comparison surface.
func (c *RunnerConfig) AsMap() map[string]interface{} {
	labels := append([]string(nil), c.Labels...)
	return map[string]interface{}{
		"version":         c.Version,
		"labels":          labels,
		"work_dir":        c.WorkDir,
		"service_name":    c.ServiceName,
		"installed":       c.Installed,
		"service_running": c.ServiceRunning,
		"service_enabled": c.ServiceEnabled,
	}
}

// ToYAML serializes the configuration to YAML.
func (c *RunnerConfig) ToYAML() ([]byte, error) { return yaml.Marshal(c) }

// FromYAML deserializes YAML into the configuration.
func (c *RunnerConfig) FromYAML(data []byte) error { return yaml.Unmarshal(data, c) }

// Validate ensures the desired configuration is well-formed before any host
// mutation. Observed-only fields are not validated.
func (c *RunnerConfig) Validate() error {
	if strings.TrimSpace(c.Version) == "" {
		return fmt.Errorf("%w: version is required", modules.ErrInvalidInput)
	}
	if strings.TrimSpace(c.AgentURL) == "" {
		return fmt.Errorf("%w: agent_url is required", modules.ErrInvalidInput)
	}
	if !strings.HasPrefix(c.AgentURL, "https://") && !strings.HasPrefix(c.AgentURL, "http://") {
		return fmt.Errorf("%w: agent_url must be an http(s) URL", modules.ErrInvalidInput)
	}
	if !sha256HexPattern.MatchString(c.AgentSHA256) {
		return fmt.Errorf("%w: agent_sha256 must be a 64-character hex SHA-256", modules.ErrInvalidInput)
	}
	if strings.TrimSpace(c.WorkDir) == "" {
		return fmt.Errorf("%w: work_dir is required", modules.ErrInvalidInput)
	}
	if !serviceNamePattern.MatchString(c.ServiceName) {
		return fmt.Errorf("%w: service_name %q contains invalid characters", modules.ErrInvalidInput, c.ServiceName)
	}
	for _, l := range c.Labels {
		if !labelPattern.MatchString(l) {
			return fmt.Errorf("%w: label %q contains invalid characters (allowed: alphanumeric, '.', '_', '-')", modules.ErrInvalidInput, l)
		}
	}
	return nil
}

// GetManagedFields returns the fields this configuration manages for drift.
func (c *RunnerConfig) GetManagedFields() []string {
	return []string{"version", "labels", "service_running", "service_enabled"}
}

// fromMap populates the config from a generic AsMap (used when the engine passes
// a non-RunnerConfig ConfigState).
func (c *RunnerConfig) fromMap(m map[string]interface{}) error {
	c.Version, _ = m["version"].(string)
	c.AgentURL, _ = m["agent_url"].(string)
	c.AgentSHA256, _ = m["agent_sha256"].(string)
	c.WorkDir, _ = m["work_dir"].(string)
	c.ServiceName, _ = m["service_name"].(string)
	switch v := m["labels"].(type) {
	case []string:
		c.Labels = append([]string(nil), v...)
	case []interface{}:
		for _, e := range v {
			if s, ok := e.(string); ok {
				c.Labels = append(c.Labels, s)
			}
		}
	}
	return nil
}

// runnerState is the on-disk drift marker the module owns.
type runnerState struct {
	Version     string   `json:"version"`
	Labels      []string `json:"labels"`
	ServiceName string   `json:"service_name"`
}

// statePath returns the marker path for a work directory.
func statePath(workDir string) string {
	return filepath.Join(workDir, stateFileName)
}

// readState loads the marker for workDir. A missing marker is not an error — it
// means the runner has never been converged (zero-value state).
func readState(workDir string) (runnerState, error) {
	var st runnerState
	data, err := os.ReadFile(statePath(workDir)) // #nosec G304 - path derived from validated work_dir
	if err != nil {
		if os.IsNotExist(err) {
			return runnerState{}, nil
		}
		return runnerState{}, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return runnerState{}, fmt.Errorf("parse runner state marker: %w", err)
	}
	return st, nil
}

// writeState persists the marker for workDir with 0600 permissions, creating the
// work directory if necessary.
func writeState(workDir string, st runnerState) error {
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(workDir), data, 0o600)
}
