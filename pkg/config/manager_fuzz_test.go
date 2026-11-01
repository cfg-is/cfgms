// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"testing"

	"gopkg.in/yaml.v3"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
)

// FuzzUnmarshalStewardConfig fuzzes the YAML-unmarshal-then-validate path that
// GetConfiguration and GetConfigurationWithInheritance both call when they read
// a stored config entry (manager.go:97, :121). It exercises the full end-to-end
// parse boundary a malformed `cfg push` payload would hit.
func FuzzUnmarshalStewardConfig(f *testing.F) {
	// Seed with valid StewardConfig YAML fixtures matching what manager_test.go uses.
	seeds := []string{
		// Minimal valid config
		`steward:
  id: fuzz-steward
  mode: standalone
  logging:
    level: info
    format: text
`,
		// Config with resources
		`steward:
  id: fuzz-steward-2
  mode: standalone
  logging:
    level: debug
resources:
  - name: test-resource
    module: directory
    config:
      path: /opt/test
`,
		// Controller mode config
		`steward:
  id: fuzz-steward-3
  mode: controller
  logging:
    level: warn
    format: json
`,
		// Config with modules map
		`steward:
  id: fuzz-steward-4
  mode: standalone
  logging:
    level: error
modules:
  file: file
  service: service
resources:
  - name: r1
    module: file
    config:
      path: /tmp/x
`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var config stewardconfig.StewardConfig
		if err := yaml.Unmarshal(data, &config); err != nil {
			// Unmarshal errors are expected for arbitrary input; not a bug.
			return
		}
		// Run the real validation path — panics here are bugs.
		_ = stewardconfig.ValidateConfiguration(config)
	})
}
