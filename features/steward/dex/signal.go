// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dex

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ErrPlatformNotSupported is returned on non-Windows platforms where ETW/WMI
// acquisition is unavailable.
var ErrPlatformNotSupported = errors.New("dex: platform not supported (Windows only)")

// SignalClass identifies which DEX signal category a record belongs to.
type SignalClass string

const (
	// SignalAppHang covers app-hang and UI-responsiveness events from Win32k.
	SignalAppHang SignalClass = "app_hang"

	// SignalSMART covers storage predictive-failure data from MSStorageDriver.
	SignalSMART SignalClass = "smart"

	// SignalThermal covers thermal zone temperatures and CPU throttle from MSAcpi.
	SignalThermal SignalClass = "thermal"

	// SignalDiskIO covers disk I/O wait time and queue depth from Kernel-Disk.
	SignalDiskIO SignalClass = "disk_io"

	// SignalHardFault covers hard-fault paging from Kernel-PerfInfo.
	SignalHardFault SignalClass = "hard_fault"

	// SignalNetwork covers network latency, jitter, and DNS from DNS-Client.
	SignalNetwork SignalClass = "network"
)

// ProviderMechanism describes how a signal is acquired (ETW or WMI).
type ProviderMechanism string

const (
	MechanismETW ProviderMechanism = "etw"
	MechanismWMI ProviderMechanism = "wmi"
)

// ReachabilityResult records whether a single provider/class was reachable on
// this machine and what exact mechanism was used.
type ReachabilityResult struct {
	Class     SignalClass       `json:"class"`
	Mechanism ProviderMechanism `json:"mechanism"`
	// Provider is the ETW provider name or WMI class name.
	Provider  string `json:"provider"`
	Reachable bool   `json:"reachable"`
	// Error holds a human-readable reason when Reachable is false.
	Error string `json:"error,omitempty"`
}

// OverheadSample records a single CPU-overhead measurement.
type OverheadSample struct {
	// DurationSec is the measurement window length in seconds.
	DurationSec float64 `json:"duration_sec"`
	// CPUPercent is the average single-core CPU percentage consumed by the
	// spike process during the window.
	CPUPercent float64 `json:"cpu_percent"`
	// BudgetPercent is the target ceiling (always 1.0 for this spike).
	BudgetPercent float64 `json:"budget_percent"`
	// WithinBudget is true when CPUPercent ≤ BudgetPercent.
	WithinBudget bool `json:"within_budget"`
}

// SpikeRecord is a single JSON-line emitted by the spike.
type SpikeRecord struct {
	// Timestamp is set by the sink at emission time.
	Timestamp time.Time `json:"ts"`
	// Kind is "reachability", "overhead", or "event".
	Kind string `json:"kind"`

	// Reachability is set when Kind == "reachability".
	Reachability *ReachabilityResult `json:"reachability,omitempty"`

	// Overhead is set when Kind == "overhead".
	Overhead *OverheadSample `json:"overhead,omitempty"`

	// Event is set when Kind == "event" — a raw signal observation.
	Event map[string]any `json:"event,omitempty"`
}

// Sink writes spike records as JSON lines to an io.Writer; safe for concurrent use.
type Sink struct {
	mu  sync.Mutex
	w   io.Writer
	enc *json.Encoder
}

// NewSink returns a Sink that writes JSON lines to w.
func NewSink(w io.Writer) *Sink {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Sink{w: w, enc: enc}
}

// WriteReachability emits a reachability result.
func (s *Sink) WriteReachability(r ReachabilityResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(SpikeRecord{
		Timestamp:    time.Now().UTC(),
		Kind:         "reachability",
		Reachability: &r,
	})
}

// WriteOverhead emits a CPU overhead sample.
func (s *Sink) WriteOverhead(o OverheadSample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(SpikeRecord{
		Timestamp: time.Now().UTC(),
		Kind:      "overhead",
		Overhead:  &o,
	})
}

// WriteEvent emits a raw signal observation.
func (s *Sink) WriteEvent(class SignalClass, fields map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(SpikeRecord{
		Timestamp: time.Now().UTC(),
		Kind:      "event",
		Event:     mergeClass(class, fields),
	})
}

func mergeClass(class SignalClass, fields map[string]any) map[string]any {
	out := make(map[string]any, len(fields)+1)
	out["class"] = string(class)
	for k, v := range fields {
		out[k] = v
	}
	return out
}

// SpikeConfig holds runtime parameters for the acquisition spike.
type SpikeConfig struct {
	// SessionName is the ETW session name registered with the OS.
	SessionName string

	// OverheadWindowSec is how long to measure CPU overhead (seconds).
	OverheadWindowSec int

	// MaxEventsPerClass caps events collected per signal class before stopping
	// (avoids flooding stdout during a PoC run).
	MaxEventsPerClass int
}

// DefaultConfig returns sensible defaults for a PoC run.
func DefaultConfig() SpikeConfig {
	return SpikeConfig{
		SessionName:       "cfgms-dex-spike",
		OverheadWindowSec: 30,
		MaxEventsPerClass: 10,
	}
}

// SpikeReport is the final summary returned by Collector.Run.
type SpikeReport struct {
	// Reachability holds one entry per probed signal class.
	Reachability []ReachabilityResult `json:"reachability"`
	// Overhead is the CPU measurement taken while actively collecting.
	Overhead OverheadSample `json:"overhead"`
	// TotalEvents is the number of raw signal events successfully written to the sink.
	TotalEvents int `json:"total_events"`
	// SinkErrors is the number of sink write failures during collection.
	SinkErrors int `json:"sink_errors,omitempty"`
}

// String returns a human-readable summary of the spike report suitable for
// embedding in a tracking comment or PR body.
func (r SpikeReport) String() string {
	out := "DEX Windows Acquisition Spike — Results\n"
	out += "========================================\n\n"

	out += "Signal Reachability\n"
	out += "-------------------\n"
	for _, rr := range r.Reachability {
		status := "YES"
		if !rr.Reachable {
			status = "NO"
		}
		detail := fmt.Sprintf("%-14s %-4s  %s/%s", string(rr.Class), status, rr.Mechanism, rr.Provider)
		if rr.Error != "" {
			detail += "  (" + rr.Error + ")"
		}
		out += detail + "\n"
	}

	out += "\nCPU Overhead\n"
	out += "------------\n"
	out += fmt.Sprintf("Window:  %.0f s\n", r.Overhead.DurationSec)
	out += fmt.Sprintf("CPU %%:   %.3f %%\n", r.Overhead.CPUPercent)
	out += fmt.Sprintf("Budget:  %.1f %%\n", r.Overhead.BudgetPercent)
	verdict := "PASS (within budget)"
	if !r.Overhead.WithinBudget {
		verdict = "FAIL (exceeds budget)"
	}
	out += fmt.Sprintf("Verdict: %s\n", verdict)

	out += fmt.Sprintf("\nTotal signal events captured: %d\n", r.TotalEvents)
	if r.SinkErrors > 0 {
		out += fmt.Sprintf("Sink write errors (dropped): %d\n", r.SinkErrors)
	}
	return out
}
