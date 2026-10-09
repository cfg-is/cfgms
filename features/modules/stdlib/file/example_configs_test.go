// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package file

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type exampleResource struct {
	Name   string                 `yaml:"name"`
	Module string                 `yaml:"module"`
	Config map[string]interface{} `yaml:"config"`
}

type exampleConfig struct {
	Resources []exampleResource `yaml:"resources"`
}

var driveLetterPrefix = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

// isAbsPlatformNeutral reports whether p is absolute on either POSIX or
// Windows, independent of the platform running the test.
func isAbsPlatformNeutral(p string) bool {
	return strings.HasPrefix(p, "/") || driveLetterPrefix.MatchString(p)
}

// pathWithin reports whether path equals or lies under base, comparing with
// separators normalised and case-insensitively for drive-letter paths.
func pathWithin(path, base string) bool {
	p := strings.ReplaceAll(path, `\`, "/")
	b := strings.TrimRight(strings.ReplaceAll(base, `\`, "/"), "/")
	if driveLetterPrefix.MatchString(base) {
		p, b = strings.ToLower(p), strings.ToLower(b)
	}
	return p == b || strings.HasPrefix(p, b+"/")
}

// checkFileResource returns the problems found with a file/directory resource.
func checkFileResource(r exampleResource) []string {
	var problems []string
	cfg := extractFileConfig(r.Config)

	switch {
	case cfg.AllowedBasePath == "":
		problems = append(problems, "allowed_base_path is missing")
	case !isAbsPlatformNeutral(cfg.AllowedBasePath):
		problems = append(problems, "allowed_base_path is not absolute: "+cfg.AllowedBasePath)
	case cfg.Path == "":
		problems = append(problems, "path is missing")
	case !pathWithin(cfg.Path, cfg.AllowedBasePath):
		problems = append(problems, "path "+cfg.Path+" is not under allowed_base_path "+cfg.AllowedBasePath)
	}

	if r.Module == "directory" && cfg.Type != "directory" {
		problems = append(problems, "module \"directory\" requires explicit type: directory")
	}
	return problems
}

func TestExampleConfigs_FileAndDirectoryResourcesValid(t *testing.T) {
	docsDir := filepath.Join("..", "..", "..", "..", "docs")
	checked := 0

	err := filepath.WalkDir(docsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".cfg" {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 -- walks the repo's own docs tree
		require.NoError(t, err, path)

		var cfg exampleConfig
		require.NoError(t, yaml.Unmarshal(data, &cfg), "parse %s", path)

		for _, r := range cfg.Resources {
			if r.Module != "file" && r.Module != "directory" {
				continue
			}
			checked++
			for _, problem := range checkFileResource(r) {
				assert.Failf(t, "invalid example resource", "%s: resource %q: %s", path, r.Name, problem)
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.Positive(t, checked, "no file or directory resources found under docs/")
}

func TestExampleConfigs_CheckRejectsBadResource(t *testing.T) {
	noBase := exampleResource{Name: "no-base", Module: "file",
		Config: map[string]interface{}{"path": "/etc/app.conf"}}
	problems := checkFileResource(noBase)
	require.Len(t, problems, 1)
	assert.Contains(t, problems[0], "allowed_base_path is missing")

	noType := exampleResource{Name: "no-type", Module: "directory",
		Config: map[string]interface{}{"path": "/var/app", "allowed_base_path": "/var"}}
	problems = checkFileResource(noType)
	require.Len(t, problems, 1)
	assert.Contains(t, problems[0], "type: directory")

	relative := exampleResource{Name: "relative", Module: "file",
		Config: map[string]interface{}{"path": "app/x", "allowed_base_path": "app"}}
	assert.NotEmpty(t, checkFileResource(relative))

	outside := exampleResource{Name: "outside", Module: "file",
		Config: map[string]interface{}{"path": "/etc/x", "allowed_base_path": "/var"}}
	assert.NotEmpty(t, checkFileResource(outside))

	good := exampleResource{Name: "win", Module: "directory",
		Config: map[string]interface{}{"type": "directory", "path": `D:\Shares\Data`, "allowed_base_path": `d:\shares`}}
	assert.Empty(t, checkFileResource(good))
}
