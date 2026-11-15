// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package timemodule

import (
	"errors"
	"os/exec"
	"strconv"
	"testing"

	"github.com/cfgis/cfgms/pkg/logging"
)

// w32tmAvailable returns true when the Windows Time Service is available.
func w32tmAvailable() bool {
	return exec.Command("w32tm", "/query", "/configuration").Run() == nil
}

// capturedW32tmConfiguration is a captured "w32tm /query /configuration"
// excerpt from a domain-joined member (CRLF line endings, as w32tm emits).
const capturedW32tmConfiguration = "[Configuration]\r\n\r\n" +
	"EventLogFlags: 2 (Local)\r\n" +
	"AnnounceFlags: 10 (Local)\r\n" +
	"MaxPosPhaseCorrection: 54000 (Local)\r\n\r\n" +
	"[TimeProviders]\r\n\r\n" +
	"NtpClient (Local)\r\n" +
	"DllName: C:\\Windows\\system32\\w32time.DLL (Local)\r\n" +
	"Enabled: 1 (Local)\r\n" +
	"NtpServer: time.windows.com,0x9 (Local)\r\n" +
	"Type: NT5DS (Local)\r\n"

// TestParseW32tmConfiguration_CapturedOutput parses a captured w32tm output.
func TestParseW32tmConfiguration_CapturedOutput(t *testing.T) {
	cfg := parseW32tmConfiguration(capturedW32tmConfiguration)
	if cfg.source != "domain" {
		t.Errorf("source = %q, want domain (Type: NT5DS)", cfg.source)
	}
	if !cfg.syncEnabled {
		t.Error("syncEnabled = false, want true (NT5DS is syncing)")
	}
	if cfg.reliable {
		t.Error("reliable = true, want false (AnnounceFlags 10 = 0xA has no 0x4 bit)")
	}
	if len(cfg.servers) != 1 || cfg.servers[0] != "time.windows.com" {
		t.Errorf("servers = %v, want [time.windows.com]", cfg.servers)
	}
}

// TestParseW32tmConfiguration_Type covers the Type: line: NTP and NT5DS mean
// sync enabled (manual/domain); NoSync means disabled.
func TestParseW32tmConfiguration_Type(t *testing.T) {
	cases := []struct {
		line       string
		wantSource string
		wantSync   bool
	}{
		{"Type: NTP (Local)", "manual", true},
		{"Type: NT5DS (Local)", "domain", true},
		{"Type: nt5ds", "domain", true},
		{"Type: NoSync (Local)", "manual", false},
		{"Type: nosync", "manual", false},
		{"Type: AllSync (Local)", "manual", true},
	}
	for _, tc := range cases {
		cfg := parseW32tmConfiguration(tc.line + "\r\n")
		if cfg.source != tc.wantSource || cfg.syncEnabled != tc.wantSync {
			t.Errorf("%q: got source=%q sync=%v, want source=%q sync=%v",
				tc.line, cfg.source, cfg.syncEnabled, tc.wantSource, tc.wantSync)
		}
	}
}

// TestParseW32tmConfiguration_AnnounceFlags verifies bit 0x4 means reliable.
func TestParseW32tmConfiguration_AnnounceFlags(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"AnnounceFlags: 10 (Local)", false}, // 0xA: member / non-reliable
		{"AnnounceFlags: 5 (Local)", true},   // 0x5: reliable (forest-root PDC)
		{"AnnounceFlags: 4 (Local)", true},
		{"AnnounceFlags: 12 (Local)", true}, // 0xC
		{"AnnounceFlags: 0 (Local)", false},
		{"AnnounceFlags: 0x5 (Local)", true},
		{"AnnounceFlags: garbage (Local)", false},
		{"", false},
	}
	for _, tc := range cases {
		cfg := parseW32tmConfiguration(tc.line + "\r\n")
		if cfg.reliable != tc.want {
			t.Errorf("%q: reliable = %v, want %v", tc.line, cfg.reliable, tc.want)
		}
	}
}

// TestParseW32tmConfiguration_ServerParsing verifies the NtpServer line parsing:
// trailing parenthetical annotations and comma-delimited polling flags are
// stripped from each server token.
func TestParseW32tmConfiguration_ServerParsing(t *testing.T) {
	cases := []struct {
		name string
		line string
		want []string
	}{
		{"single server with polling flag", "NtpServer: time.windows.com,0x9 (Local)", []string{"time.windows.com"}},
		{"multiple servers", "NtpServer: ntp1.example.com,0x9 ntp2.example.com,0x9 (Local)", []string{"ntp1.example.com", "ntp2.example.com"}},
		{"server without polling flag", "NtpServer: pool.ntp.org (Local)", []string{"pool.ntp.org"}},
		{"empty NtpServer", "NtpServer:  (Local)", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseW32tmConfiguration(tc.line).servers
			if len(got) != len(tc.want) {
				t.Fatalf("servers = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("server[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// fakeRegistry is a map-backed registryAccess, the test seam for the OS
// registry. Keys are lower-cased "path|name" for values and bare paths for keys.
type fakeRegistry struct {
	keys   map[string]bool
	values map[string]uint32
	writes int
}

func newFakeRegistry(guest bool, enabled *uint32) *fakeRegistry {
	r := &fakeRegistry{keys: map[string]bool{}, values: map[string]uint32{}}
	if guest {
		r.keys[hypervGuestKey] = true
	}
	r.keys[vmicTimeProviderKey] = true
	if enabled != nil {
		r.values[vmicTimeProviderKey+"|"+vmicEnabledValue] = *enabled
	}
	return r
}

func (r *fakeRegistry) keyExists(path string) (bool, error) { return r.keys[path], nil }

func (r *fakeRegistry) readDWORD(path, name string) (uint32, bool, error) {
	v, ok := r.values[path+"|"+name]
	return v, ok, nil
}

func (r *fakeRegistry) writeDWORD(path, name string, value uint32) error {
	if !r.keys[path] {
		return errors.New("key does not exist")
	}
	r.values[path+"|"+name] = value
	r.writes++
	return nil
}

func u32(v uint32) *uint32 { return &v }

func newTestExecutor(reg registryAccess, restarts *int) *windowsExecutor {
	return &windowsExecutor{
		reg: reg,
		restartW32Time: func() error {
			*restarts++
			return nil
		},
		logger: logging.ForModule("time"),
	}
}

// TestApplyHyperVTimeProvider covers set / no-op-on-unchanged behaviour.
func TestApplyHyperVTimeProvider(t *testing.T) {
	cases := []struct {
		name         string
		guest        bool
		initial      *uint32
		setting      string
		wantValue    *uint32
		wantRestarts int
	}{
		{"disable when enabled", true, u32(1), "disabled", u32(0), 1},
		{"disable when already disabled is a no-op", true, u32(0), "disabled", u32(0), 0},
		{"disable when value absent is a no-op", true, nil, "disabled", nil, 0},
		{"enable when disabled", true, u32(0), "enabled", u32(1), 1},
		{"enable when already enabled is a no-op", true, u32(1), "enabled", u32(1), 0},
		{"enable when value absent writes", true, nil, "enabled", u32(1), 1},
		{"unmanaged leaves value alone", true, u32(1), "", u32(1), 0},
		{"non-guest is a no-op", false, u32(1), "disabled", u32(1), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := newFakeRegistry(tc.guest, tc.initial)
			restarts := 0
			e := newTestExecutor(reg, &restarts)

			if err := e.applyHyperVTimeProvider(tc.setting); err != nil {
				t.Fatalf("applyHyperVTimeProvider: %v", err)
			}
			if restarts != tc.wantRestarts {
				t.Errorf("w32time restarts = %d, want %d", restarts, tc.wantRestarts)
			}
			got, found := reg.values[vmicTimeProviderKey+"|"+vmicEnabledValue]
			if tc.wantValue == nil {
				if found {
					t.Errorf("Enabled = %d, want absent", got)
				}
			} else if !found || got != *tc.wantValue {
				t.Errorf("Enabled = %d (found=%v), want %d", got, found, *tc.wantValue)
			}
			if tc.wantRestarts == 0 && reg.writes != 0 {
				t.Errorf("registry writes = %d, want 0 when unchanged", reg.writes)
			}
		})
	}
}

// TestApplyHyperVTimeProvider_Errors verifies write and restart failures surface.
func TestApplyHyperVTimeProvider_Errors(t *testing.T) {
	t.Run("missing provider key fails the write", func(t *testing.T) {
		reg := newFakeRegistry(true, nil)
		delete(reg.keys, vmicTimeProviderKey)
		restarts := 0
		e := newTestExecutor(reg, &restarts)
		if err := e.applyHyperVTimeProvider("enabled"); err == nil {
			t.Fatal("expected an error when the provider key is missing")
		}
		if restarts != 0 {
			t.Errorf("restarts = %d, want 0 after failed write", restarts)
		}
	})

	t.Run("restart failure is returned", func(t *testing.T) {
		reg := newFakeRegistry(true, u32(1))
		e := newTestExecutor(reg, new(int))
		e.restartW32Time = func() error { return errors.New("scm unavailable") }
		if err := e.applyHyperVTimeProvider("disabled"); err == nil {
			t.Fatal("expected restart failure to be returned")
		}
	})
}

// TestGetHyperVTimeProvider verifies getState's read-back of VMICTimeProvider.
func TestGetHyperVTimeProvider(t *testing.T) {
	cases := []struct {
		name    string
		guest   bool
		initial *uint32
		want    string
	}{
		{"guest enabled", true, u32(1), "enabled"},
		{"guest disabled", true, u32(0), "disabled"},
		{"guest value absent", true, nil, "disabled"},
		{"non-guest is unreported", false, u32(1), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestExecutor(newFakeRegistry(tc.guest, tc.initial), new(int))
			got, err := e.getHyperVTimeProvider()
			if err != nil {
				t.Fatalf("getHyperVTimeProvider: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIsAccessDeniedExitError verifies the exit-code classification getNTPConfig
// relies on to map w32tm's access-denied failure to modules.ErrInsufficientPrivilege
// (Issue #4147). Uses a synthetic exit code from cmd.exe rather than depending on
// this session's actual elevation state, so the classification itself is
// deterministic regardless of whether the test runner is elevated.
func TestIsAccessDeniedExitError(t *testing.T) {
	runWithExitCode := func(t *testing.T, code int) error {
		t.Helper()
		return exec.Command("cmd", "/c", "exit", "/b", strconv.Itoa(code)).Run()
	}

	t.Run("access denied HRESULT is classified as access denied", func(t *testing.T) {
		err := runWithExitCode(t, errAccessDeniedHRESULT)
		if err == nil {
			t.Fatal("exit /b with a non-zero code must return a non-nil error")
		}
		if !isAccessDeniedExitError(err) {
			t.Errorf("isAccessDeniedExitError(%v) = false, want true", err)
		}
	})

	t.Run("an unrelated non-zero exit code is not classified as access denied", func(t *testing.T) {
		err := runWithExitCode(t, 1)
		if err == nil {
			t.Fatal("exit /b 1 must return a non-nil error")
		}
		if isAccessDeniedExitError(err) {
			t.Errorf("isAccessDeniedExitError(%v) = true, want false", err)
		}
	})

	t.Run("success is not classified as access denied", func(t *testing.T) {
		if err := runWithExitCode(t, 0); err != nil {
			t.Fatalf("exit /b 0 must succeed, got %v", err)
		}
	})

	t.Run("a non-ExitError is never classified as access denied", func(t *testing.T) {
		_, err := exec.LookPath("this-binary-does-not-exist-cfgms-4147")
		if err == nil {
			t.Fatal("expected LookPath to fail for a nonexistent binary")
		}
		if isAccessDeniedExitError(err) {
			t.Errorf("isAccessDeniedExitError(%v) = true, want false for a non-ExitError", err)
		}
	})
}

// TestWindowsExecutor_GetState verifies the full getState round-trip on Windows
// when w32tm and the Windows Time Service are available.
func TestWindowsExecutor_GetState(t *testing.T) {
	if !w32tmAvailable() {
		t.Skip("skipping: w32tm not available or Windows Time Service is not running")
	}

	e := newExecutor()
	state, err := e.getState()
	if err != nil {
		t.Fatalf("getState() error: %v", err)
	}

	if state.Timezone == "" {
		t.Error("getState() returned empty Timezone")
	}
	// NTPServers may be empty (valid when no peers are configured).
	// NTPSyncEnabled is boolean — no assertion on the specific value.
}
