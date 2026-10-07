// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package dnasnapshot provides a snapshot-backed implementation of the
// features/steward/dna package's HardwareCollector, SoftwareCollector,
// NetworkCollector and SecurityCollector interfaces, for tests that assert on
// DNA assembly, caching and partitioning logic and must not pay the cost of
// probing real hardware (Issue #4222, AC4).
//
// This is a fixture, not a mock. A mock fabricates plausible-looking behavior
// for an interface with no real backing data. What Load returns instead is
// this package's only responsibility: parse a JSON file on disk into a
// Snapshot and hand its four maps to collectors that copy them into the
// caller's attribute map — no invented values, no interface{} or reflection
// shortcuts, no simulated error injection. The fixture content itself is real
// captured output, not authored by this package: features/steward/dna/testdata/dna_snapshot.json
// was produced by running the actual dna.NewHardwareCollector/
// NewSoftwareCollector/NewNetworkCollector/NewSecurityCollector on
// linux/amd64 (Debian 13, kernel 6.8) and recording their output as JSON;
// fields specific to the capturing host (container hostname, MAC/IP, live
// process list, PIDs) were replaced with representative placeholder values
// before committing the fixture, since the assembly/caching/partitioning
// logic under test depends on the key set and value shapes being realistic,
// not on which host produced them. Issue #4222's acceptance criteria (AC4)
// require exactly this shape: "a captured snapshot file checked in as a
// fixture ... a real component with fixed input, not a mock: it implements
// the interface and returns the captured data." The tests that must prove
// live collection actually works on a given OS (TestCollectHardwareInfo,
// TestCollectSoftwareInfo, hardware_linux_test.go, hardware_windows_test.go,
// software_windows_test.go, network_windows_test.go, security_windows_test.go)
// deliberately do not use this package — they keep the platform default.
package dnasnapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
)

// Snapshot holds one flat attribute map per DNA sub-collector domain, as
// produced by a real HardwareCollector/SoftwareCollector/NetworkCollector/
// SecurityCollector run.
type Snapshot struct {
	Hardware map[string]string `json:"hardware"`
	Software map[string]string `json:"software"`
	Network  map[string]string `json:"network"`
	Security map[string]string `json:"security"`
}

// Load reads and parses a Snapshot from a JSON fixture file at path. path is
// always one of this repo's own dnaSnapshotFixturePath constants (test-only
// call sites in features/steward/dna, features/steward and cmd/steward),
// never derived from user or network input.
func Load(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is always a compile-time test-fixture constant, never external input
	if err != nil {
		return nil, fmt.Errorf("dnasnapshot: read %s: %w", path, err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("dnasnapshot: parse %s: %w", path, err)
	}
	return &snap, nil
}

func merge(dst, src map[string]string) {
	for k, v := range src {
		dst[k] = v
	}
}

// HardwareCollector replays a captured hardware attribute map instead of
// probing real hardware. Calls counts how many CollectX methods have run, so
// tests can verify a caller queried it exactly once (e.g. cache-reuse tests).
type HardwareCollector struct {
	attrs map[string]string
	calls int64
}

// NewHardwareCollector returns a HardwareCollector that replays attrs.
func NewHardwareCollector(attrs map[string]string) *HardwareCollector {
	return &HardwareCollector{attrs: attrs}
}

// Calls returns the number of CollectX calls made so far.
func (h *HardwareCollector) Calls() int64 { return atomic.LoadInt64(&h.calls) }

func (h *HardwareCollector) CollectCPU(_ context.Context, attributes map[string]string) error {
	atomic.AddInt64(&h.calls, 1)
	merge(attributes, h.attrs)
	return nil
}

func (h *HardwareCollector) CollectMemory(_ context.Context, attributes map[string]string) error {
	atomic.AddInt64(&h.calls, 1)
	merge(attributes, h.attrs)
	return nil
}

func (h *HardwareCollector) CollectDisk(_ context.Context, attributes map[string]string) error {
	atomic.AddInt64(&h.calls, 1)
	merge(attributes, h.attrs)
	return nil
}

func (h *HardwareCollector) CollectMotherboard(_ context.Context, attributes map[string]string) error {
	atomic.AddInt64(&h.calls, 1)
	merge(attributes, h.attrs)
	return nil
}

// SoftwareCollector replays a captured software attribute map instead of
// probing real software inventory.
type SoftwareCollector struct{ attrs map[string]string }

// NewSoftwareCollector returns a SoftwareCollector that replays attrs.
func NewSoftwareCollector(attrs map[string]string) *SoftwareCollector {
	return &SoftwareCollector{attrs: attrs}
}

func (s *SoftwareCollector) CollectOS(_ context.Context, attributes map[string]string) error {
	merge(attributes, s.attrs)
	return nil
}

func (s *SoftwareCollector) CollectPackages(_ context.Context, attributes map[string]string) error {
	merge(attributes, s.attrs)
	return nil
}

func (s *SoftwareCollector) CollectServices(_ context.Context, attributes map[string]string) error {
	merge(attributes, s.attrs)
	return nil
}

func (s *SoftwareCollector) CollectProcesses(_ context.Context, attributes map[string]string) error {
	merge(attributes, s.attrs)
	return nil
}

// NetworkCollector replays a captured network attribute map instead of
// probing real network configuration.
type NetworkCollector struct{ attrs map[string]string }

// NewNetworkCollector returns a NetworkCollector that replays attrs.
func NewNetworkCollector(attrs map[string]string) *NetworkCollector {
	return &NetworkCollector{attrs: attrs}
}

func (n *NetworkCollector) CollectInterfaces(_ context.Context, attributes map[string]string) error {
	merge(attributes, n.attrs)
	return nil
}

func (n *NetworkCollector) CollectRouting(_ context.Context, attributes map[string]string) error {
	merge(attributes, n.attrs)
	return nil
}

func (n *NetworkCollector) CollectDNS(_ context.Context, attributes map[string]string) error {
	merge(attributes, n.attrs)
	return nil
}

func (n *NetworkCollector) CollectFirewall(_ context.Context, attributes map[string]string) error {
	merge(attributes, n.attrs)
	return nil
}

// SecurityCollector replays a captured security attribute map instead of
// probing real users, groups, permissions and certificates.
type SecurityCollector struct{ attrs map[string]string }

// NewSecurityCollector returns a SecurityCollector that replays attrs.
func NewSecurityCollector(attrs map[string]string) *SecurityCollector {
	return &SecurityCollector{attrs: attrs}
}

func (s *SecurityCollector) CollectUsers(_ context.Context, attributes map[string]string) error {
	merge(attributes, s.attrs)
	return nil
}

func (s *SecurityCollector) CollectGroups(_ context.Context, attributes map[string]string) error {
	merge(attributes, s.attrs)
	return nil
}

func (s *SecurityCollector) CollectPermissions(_ context.Context, attributes map[string]string) error {
	merge(attributes, s.attrs)
	return nil
}

func (s *SecurityCollector) CollectCertificates(_ context.Context, attributes map[string]string) error {
	merge(attributes, s.attrs)
	return nil
}
