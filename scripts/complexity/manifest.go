// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/scripts/complexity/analyzer"
)

// ManifestVersion is the supported manifest schema version.
const ManifestVersion = 1

// segmentNames are the only segment names a manifest may define.
var segmentNames = map[string]bool{
	"controller": true, "steward": true, "workflow": true, "modules": true,
	"pkg": true, "cmd": true, "features-shared": true,
}

// Segment is one named partition of the production population.
type Segment struct {
	Name      string   `json:"name"`
	Paths     []string `json:"paths"`
	Covers    string   `json:"covers"`
	CannotSee string   `json:"cannot_see"`
}

// Manifest is the committed population manifest.
type Manifest struct {
	Version  int       `json:"version"`
	Segments []Segment `json:"segments"`
}

// LoadManifest parses and validates manifest bytes.
func LoadManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("manifest version %d, want %d", m.Version, ManifestVersion)
	}
	seen := map[string]bool{}
	type owned struct{ seg, prefix string }
	var all []owned
	for _, s := range m.Segments {
		if !segmentNames[s.Name] {
			return fmt.Errorf("manifest: unknown segment name %q", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("manifest: duplicate segment name %q", s.Name)
		}
		seen[s.Name] = true
		if strings.TrimSpace(s.Covers) == "" {
			return fmt.Errorf("manifest: segment %q has empty covers", s.Name)
		}
		if strings.TrimSpace(s.CannotSee) == "" {
			return fmt.Errorf("manifest: segment %q has empty cannot_see", s.Name)
		}
		if len(s.Paths) == 0 {
			return fmt.Errorf("manifest: segment %q has no paths", s.Name)
		}
		for _, p := range s.Paths {
			if err := checkPrefix(s.Name, p); err != nil {
				return err
			}
			all = append(all, owned{s.Name, p})
		}
	}
	for i, a := range all {
		for _, b := range all[i+1:] {
			if strings.HasPrefix(a.prefix, b.prefix) || strings.HasPrefix(b.prefix, a.prefix) {
				return fmt.Errorf("manifest: path %q (segment %q) overlaps %q (segment %q): claimed twice",
					a.prefix, a.seg, b.prefix, b.seg)
			}
		}
	}
	return nil
}

func checkPrefix(seg, p string) error {
	switch {
	case p == "":
		return fmt.Errorf("manifest: segment %q has an empty path", seg)
	case !strings.HasSuffix(p, "/"):
		return fmt.Errorf("manifest: segment %q path %q must end in /", seg, p)
	case strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.ContainsAny(p, "*?["):
		return fmt.Errorf("manifest: segment %q path %q must be a plain repo-relative prefix", seg, p)
	case p == "features/":
		return fmt.Errorf("manifest: segment %q path %q is too broad; name each features directory", seg, p)
	}
	return nil
}

// Assign returns the names of the segments that claim file.
func (m *Manifest) Assign(file string) []string {
	var out []string
	for _, s := range m.Segments {
		for _, p := range s.Paths {
			if strings.HasPrefix(file, p) {
				out = append(out, s.Name)
				break
			}
		}
	}
	return out
}

// BySegment partitions fns by the manifest, independently of any aggregate.
func (m *Manifest) BySegment(fns []analyzer.Function) map[string][]analyzer.Function {
	out := map[string][]analyzer.Function{}
	for _, s := range m.Segments {
		out[s.Name] = nil
	}
	for _, fn := range fns {
		for _, name := range m.Assign(fn.File) {
			out[name] = append(out[name], fn)
		}
	}
	return out
}

// UnusedPrefixes returns "segment: prefix" for every manifest path prefix
// with no measured production function.
func (m *Manifest) UnusedPrefixes(fns []analyzer.Function) []string {
	var out []string
	for _, s := range m.Segments {
		for _, p := range s.Paths {
			used := false
			for _, fn := range fns {
				if strings.HasPrefix(fn.File, p) {
					used = true
					break
				}
			}
			if !used {
				out = append(out, s.Name+": "+p)
			}
		}
	}
	return out
}
