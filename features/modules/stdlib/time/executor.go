// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package timemodule

import (
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/modules"
)

// Allowed values for the ntp_source and hyperv_host_time_provider fields.
const (
	ntpSourceManual = "manual"
	ntpSourceDomain = "domain"

	hypervProviderEnabled  = "enabled"
	hypervProviderDisabled = "disabled"
)

// defaultWindowsPeer is the peer used on Windows when ntp_source is manual and
// no ntp_servers are configured.
const defaultWindowsPeer = "time.windows.com,0x9"

// timeState holds the observed current time configuration of the host.
type timeState struct {
	// Timezone is the IANA timezone identifier (e.g. "UTC", "America/Chicago").
	Timezone string
	// NTPServers is the list of NTP server addresses, always sorted for determinism.
	NTPServers []string
	// NTPSyncEnabled indicates whether automatic NTP synchronisation is configured.
	NTPSyncEnabled bool
	// NTPSource selects where time is synchronised from: "manual" (the
	// configured peer list) or "domain" (the domain hierarchy). Empty means
	// "manual".
	NTPSource string
	// NTPReliable declares the host a reliable time source (Windows only).
	NTPReliable bool
	// HyperVHostTimeProvider is "enabled", "disabled" or empty (unmanaged).
	// It controls the Hyper-V guest time provider (Windows only).
	HyperVHostTimeProvider string
}

// effectiveNTPSource returns the ntp_source value with the default applied.
func effectiveNTPSource(source string) string {
	if source == "" {
		return ntpSourceManual
	}
	return source
}

// rejectWindowsOnlyFields returns modules.ErrInvalidInput when desired sets a
// non-default value for a field only the Windows executor supports. Linux,
// macOS and unsupported platforms call it from setState.
func rejectWindowsOnlyFields(desired timeState) error {
	if effectiveNTPSource(desired.NTPSource) != ntpSourceManual {
		return fmt.Errorf("%w: ntp_source %q is only supported on Windows", modules.ErrInvalidInput, desired.NTPSource)
	}
	if desired.NTPReliable {
		return fmt.Errorf("%w: ntp_reliable is only supported on Windows", modules.ErrInvalidInput)
	}
	if desired.HyperVHostTimeProvider != "" {
		return fmt.Errorf("%w: hyperv_host_time_provider is only supported on Windows", modules.ErrInvalidInput)
	}
	return nil
}

// buildW32tmConfigArgs returns every w32tm invocation (arguments only, without
// the executable name) needed to apply desired, in order.
//
// Precedence:
//  1. NTPSyncEnabled false: sync is switched off; the other fields are ignored.
//  2. NTPSource "domain": sync from the domain hierarchy, never reliable;
//     NTPServers is ignored.
//  3. NTPSource "manual" (default): sync from the peer list (default peer when
//     empty); reliable only when NTPReliable is true.
func buildW32tmConfigArgs(desired timeState) [][]string {
	if !desired.NTPSyncEnabled {
		return [][]string{{"/config", "/syncfromflags:no", "/update"}}
	}
	if effectiveNTPSource(desired.NTPSource) == ntpSourceDomain {
		return [][]string{{"/config", "/syncfromflags:domhier", "/reliable:no", "/update"}}
	}

	peerList := strings.Join(desired.NTPServers, " ")
	if peerList == "" {
		peerList = defaultWindowsPeer
	}
	reliable := "/reliable:no"
	if desired.NTPReliable {
		reliable = "/reliable:yes"
	}
	return [][]string{{"/config", "/manualpeerlist:" + peerList, "/syncfromflags:manual", reliable, "/update"}}
}

// timeExecutor is the platform-specific backend for host time configuration.
// Each platform (Linux, Windows, macOS) provides its own implementation via
// build tags. Unsupported platforms use the stub implementation that returns
// ErrUnsupportedPlatform.
type timeExecutor interface {
	// getState returns the current timezone and NTP configuration of the host.
	// NTPServers in the returned state are always sorted for determinism.
	getState() (timeState, error)

	// setState applies the desired timezone and NTP configuration. It is
	// idempotent: calling setState when the host is already in the desired
	// state is a no-op.
	setState(desired timeState) error
}
