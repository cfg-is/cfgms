// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package compat holds the steward compatibility harness (Issue #6314): the
// support manifest the floor is defined in, and the scenarios that run a past
// release's steward against the controller built from the change under test.
package compat

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Capability profiles a manifest entry may expect its steward to run under.
const (
	// ProfileFloor is a steward that predates capability declaration.
	ProfileFloor = "floor"
	// ProfileDeclared is a steward that declares its capabilities.
	ProfileDeclared = "declared"
)

// Entry is one supported steward release.
type Entry struct {
	Tag     string `yaml:"tag"`
	Profile string `yaml:"profile"`
}

// Manifest is test/compat/steward-support.yaml.
type Manifest struct {
	Floor    string  `yaml:"floor"`
	Stewards []Entry `yaml:"stewards"`
}

// semverPattern matches a release tag: vMAJOR.MINOR.PATCH with an optional
// dot-separated prerelease. Build metadata is not used by release tags.
var semverPattern = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

type semver struct {
	major, minor, patch uint64
	pre                 []string
}

func parseSemver(tag string) (semver, error) {
	m := semverPattern.FindStringSubmatch(tag)
	if m == nil {
		return semver{}, fmt.Errorf("tag %q is not a vMAJOR.MINOR.PATCH[-prerelease] release tag", tag)
	}
	var v semver
	for i, dst := range []*uint64{&v.major, &v.minor, &v.patch} {
		n, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return semver{}, fmt.Errorf("tag %q: %w", tag, err)
		}
		*dst = n
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, nil
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// comparePre orders prerelease identifier lists per semantic versioning: a
// release (no prerelease) sorts above any prerelease of the same version,
// numeric identifiers compare numerically and sort below alphanumeric ones.
func comparePre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aerr := strconv.ParseUint(a[i], 10, 64)
		bn, berr := strconv.ParseUint(b[i], 10, 64)
		switch {
		case aerr == nil && berr == nil:
			if c := cmpUint(an, bn); c != 0 {
				return c
			}
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return cmpUint(uint64(len(a)), uint64(len(b)))
}

// CompareSemver returns -1, 0 or 1 as release tag a sorts below, equal to or
// above b. It fails when either is not a release tag.
func CompareSemver(a, b string) (int, error) {
	va, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	vb, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for _, c := range []int{
		cmpUint(va.major, vb.major),
		cmpUint(va.minor, vb.minor),
		cmpUint(va.patch, vb.patch),
	} {
		if c != 0 {
			return c, nil
		}
	}
	return comparePre(va.pre, vb.pre), nil
}

// ParseManifest decodes and validates a support manifest: the syntax is valid
// and has no unknown keys, the floor and every tag are release tags, every
// profile is known, the floor is listed (and is the only floor-profile entry),
// tags are unique, and no entry sorts below the floor.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode steward support manifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// LoadManifest reads and validates the manifest at path.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the repository's own manifest, passed by test code
	if err != nil {
		return nil, fmt.Errorf("read steward support manifest: %w", err)
	}
	return ParseManifest(data)
}

func (m *Manifest) validate() error {
	if m.Floor == "" {
		return errors.New("steward support manifest: floor is required")
	}
	if _, err := parseSemver(m.Floor); err != nil {
		return fmt.Errorf("steward support manifest: floor: %w", err)
	}
	if len(m.Stewards) == 0 {
		return errors.New("steward support manifest: stewards must list at least one entry")
	}
	seen := make(map[string]bool, len(m.Stewards))
	floorListed := false
	for i, e := range m.Stewards {
		if _, err := parseSemver(e.Tag); err != nil {
			return fmt.Errorf("steward support manifest: stewards[%d]: %w", i, err)
		}
		if seen[e.Tag] {
			return fmt.Errorf("steward support manifest: tag %s is listed twice", e.Tag)
		}
		seen[e.Tag] = true
		if e.Profile != ProfileFloor && e.Profile != ProfileDeclared {
			return fmt.Errorf("steward support manifest: %s: profile %q must be %q or %q",
				e.Tag, e.Profile, ProfileFloor, ProfileDeclared)
		}
		c, _ := CompareSemver(e.Tag, m.Floor) // both parsed above
		if c < 0 {
			return fmt.Errorf("steward support manifest: %s sorts below the floor %s", e.Tag, m.Floor)
		}
		if (e.Tag == m.Floor) != (e.Profile == ProfileFloor) {
			return fmt.Errorf("steward support manifest: %s: profile %q is only valid for the floor tag %s",
				e.Tag, e.Profile, m.Floor)
		}
		floorListed = floorListed || e.Tag == m.Floor
	}
	if !floorListed {
		return fmt.Errorf("steward support manifest: floor %s is not listed under stewards", m.Floor)
	}
	return nil
}
