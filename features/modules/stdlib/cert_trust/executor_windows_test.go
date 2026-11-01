// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package cert_trust

import (
	"bytes"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/security"
	"github.com/cfgis/cfgms/pkg/testutil/winacct"
)

// TestParseCertutilDate verifies parseCertutilDate produces RFC3339 output for
// common certutil date formats and returns empty string for unrecognized input.
func TestParseCertutilDate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		// wantPrefix is checked when wantRFC3339 is empty (non-empty result expected).
		wantRFC3339 string
		wantEmpty   bool
	}{
		{
			name:        "en-US 12h AM midnight",
			input:       "1/15/2035 12:00 AM",
			wantRFC3339: "2035-01-15T00:00:00Z",
		},
		{
			name:        "en-US 12h PM",
			input:       "5/9/2021 11:28 PM",
			wantRFC3339: "2021-05-09T23:28:00Z",
		},
		{
			name:        "en-US 12h with leading spaces",
			input:       "  1/1/2035 12:00 AM  ",
			wantRFC3339: "2035-01-01T00:00:00Z",
		},
		{
			name:        "en-US 24h format",
			input:       "1/15/2035 23:59",
			wantRFC3339: "2035-01-15T23:59:00Z",
		},
		{
			name:        "European day-first 24h",
			input:       "15/1/2035 23:59",
			wantRFC3339: "2035-01-15T23:59:00Z",
		},
		{
			name:      "unknown locale format returns empty",
			input:     "January 15, 2035",
			wantEmpty: true,
		},
		{
			name:      "empty string returns empty",
			input:     "",
			wantEmpty: true,
		},
		{
			name:      "garbage returns empty",
			input:     "not a date",
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCertutilDate(tt.input)
			if tt.wantEmpty {
				if got != "" {
					t.Errorf("parseCertutilDate(%q) = %q, want empty string", tt.input, got)
				}
				return
			}
			if got != tt.wantRFC3339 {
				t.Errorf("parseCertutilDate(%q) = %q, want %q", tt.input, got, tt.wantRFC3339)
			}
			// Verify output is valid RFC3339.
			if !strings.HasSuffix(got, "Z") && !strings.Contains(got, "+") && !strings.Contains(got, "-0") {
				t.Errorf("parseCertutilDate(%q) = %q: does not look like RFC3339", tt.input, got)
			}
		})
	}
}

// TestParseCertutilDate_RFC3339Output verifies the output format of
// parseCertutilDate always ends in Z (UTC) so callers can rely on it.
func TestParseCertutilDate_RFC3339Output(t *testing.T) {
	validInputs := []string{
		"1/15/2035 12:00 AM",
		"5/9/2021 11:28 PM",
		"12/31/2035 11:59 PM",
	}
	for _, input := range validInputs {
		got := parseCertutilDate(input)
		if got == "" {
			t.Errorf("parseCertutilDate(%q) returned empty for a known-good input", input)
			continue
		}
		if !strings.HasSuffix(got, "Z") {
			t.Errorf("parseCertutilDate(%q) = %q: want UTC suffix 'Z' (RFC3339)", input, got)
		}
	}
}

// requireElevated skips t unless the test runs elevated. Securing the staging
// base gives it BUILTIN\Administrators as owner, and the tests hand directories
// to other principals; both need an elevated administrator, as the steward (a
// SYSTEM service) and the native Windows CI runners are.
func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator: securing the staging base assigns BUILTIN\\Administrators as owner")
	}
}

// ownerFromSDDL returns the owner SID of the security descriptor sddl.
func ownerFromSDDL(t *testing.T, sddl string) *windows.SID {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse %q: %v", sddl, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatalf("owner of %q: %v", sddl, err)
	}
	return owner
}

// addStoreCall is what a recording addStore saw when install called it.
type addStoreCall struct {
	path    string
	content []byte
	readErr error
}

// recordingExecutor returns an executor staging under base whose addStore
// records the staged path and the file's contents at the moment certutil would
// read it, then returns result. The machine trust store is never changed.
func recordingExecutor(base string, result error) (*windowsExecutor, *[]addStoreCall) {
	var calls []addStoreCall
	e := &windowsExecutor{tmpDir: base, addStore: func(path string) ([]byte, error) {
		content, err := os.ReadFile(path) // #nosec G304 - test reads the path install staged
		calls = append(calls, addStoreCall{path: path, content: content, readErr: err})
		return nil, result
	}}
	return e, &calls
}

// oldStagingName is the predictable name install used before staging moved to
// a private directory.
func oldStagingName(certDER []byte) string {
	return "cfgms-cert-install-" + certFingerprint(certDER) + ".cer"
}

// existingAdminOwnedBase creates a staging base owned by
// BUILTIN\Administrators, the state a previously secured base is in.
func existingAdminOwnedBase(t *testing.T) string {
	t.Helper()
	base := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	winacct.SetOwner(t, base, ownerFromSDDL(t, "O:BA"))
	return base
}

// isUnder reports whether path lies inside dir, ignoring case.
func isUnder(path, dir string) bool {
	return strings.HasPrefix(strings.ToLower(filepath.Clean(path)), strings.ToLower(filepath.Clean(dir))+string(filepath.Separator))
}

func TestWindowsInstall_StagesFreshFileNotOldPredictableName(t *testing.T) {
	requireElevated(t)
	_, certDER := generateTestCAPEM(t)
	wantPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	base := existingAdminOwnedBase(t)
	oldPath := filepath.Join(base, oldStagingName(certDER))
	planted := []byte("planted by another principal")
	if err := os.WriteFile(oldPath, planted, 0o600); err != nil {
		t.Fatal(err)
	}
	winacct.SetOwner(t, oldPath, ownerFromSDDL(t, "O:BA"))

	e, calls := recordingExecutor(base, nil)
	if err := e.install(certDER); err != nil {
		t.Fatalf("install: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("addStore called %d times, want 1", len(*calls))
	}
	call := (*calls)[0]
	if strings.EqualFold(call.path, oldPath) {
		t.Errorf("staged at the old predictable name %s", oldPath)
	}
	if !isUnder(call.path, base) {
		t.Errorf("staged path %s is not under the staging base %s", call.path, base)
	}
	if call.readErr != nil {
		t.Fatalf("read staged file: %v", call.readErr)
	}
	if !bytes.Equal(call.content, wantPEM) {
		t.Errorf("staged file holds %q, want the requested PEM", call.content)
	}

	got, err := os.ReadFile(oldPath) // #nosec G304 - test-controlled path
	if err != nil {
		t.Fatalf("read file at old name: %v", err)
	}
	if !bytes.Equal(got, planted) {
		t.Errorf("file at the old name was changed to %q", got)
	}
	if _, err := os.Lstat(call.path); !os.IsNotExist(err) {
		t.Errorf("staged file %s still exists after install (err=%v)", call.path, err)
	}
	assertOnlyEntries(t, base, filepath.Base(oldPath))
}

func TestWindowsInstall_FailureRemovesStagedFile(t *testing.T) {
	requireElevated(t)
	_, certDER := generateTestCAPEM(t)
	base := filepath.Join(t.TempDir(), "staging")

	e, calls := recordingExecutor(base, errors.New("certutil failed"))
	if err := e.install(certDER); err == nil {
		t.Fatal("install succeeded although certutil failed")
	}
	if len(*calls) != 1 {
		t.Fatalf("addStore called %d times, want 1", len(*calls))
	}
	if _, err := os.Lstat((*calls)[0].path); !os.IsNotExist(err) {
		t.Errorf("staged file %s still exists after a failed install (err=%v)", (*calls)[0].path, err)
	}
	assertOnlyEntries(t, base)
}

func TestWindowsInstall_SymlinkAtOldNameNotFollowed(t *testing.T) {
	requireElevated(t)
	_, certDER := generateTestCAPEM(t)
	base := existingAdminOwnedBase(t)
	target := filepath.Join(t.TempDir(), "target.pem")
	original := []byte("original target contents")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(base, oldStagingName(certDER))
	if err := os.Symlink(target, oldPath); err != nil {
		t.Skipf("creating a symbolic link needs SeCreateSymbolicLinkPrivilege, which this runner lacks: %v", err)
	}

	// Securing the base walks its entries without following links and refuses
	// the link, so nothing is staged.
	e, calls := recordingExecutor(base, nil)
	if err := e.install(certDER); !errors.Is(err, security.ErrUntrustedDirEntry) {
		t.Fatalf("install error = %v, want ErrUntrustedDirEntry", err)
	}
	if len(*calls) != 0 {
		t.Errorf("certutil ran %d times with a link in the staging base", len(*calls))
	}

	got, err := os.ReadFile(target) // #nosec G304 - test-controlled path
	if err != nil {
		t.Fatalf("read link target: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("link target was changed to %q", got)
	}
	fi, err := os.Lstat(oldPath)
	if err != nil {
		t.Fatalf("lstat link: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("link at the old name was replaced (mode %v)", fi.Mode())
	}
}

func TestWindowsInstall_RefusesBaseOwnedByUsers(t *testing.T) {
	requireElevated(t)
	_, certDER := generateTestCAPEM(t)
	base := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	winacct.SetOwner(t, base, ownerFromSDDL(t, "O:BU"))

	e, calls := recordingExecutor(base, nil)
	err := e.install(certDER)
	if !errors.Is(err, security.ErrUntrustedDirOwner) {
		t.Fatalf("install error = %v, want ErrUntrustedDirOwner", err)
	}
	if len(*calls) != 0 {
		t.Errorf("certutil ran %d times for a refused base", len(*calls))
	}
	assertOnlyEntries(t, base)
}

func TestNewExecutor_StagingBaseUnderProgramData(t *testing.T) {
	e, ok := newExecutor().(*windowsExecutor)
	if !ok {
		t.Fatalf("newExecutor returned %T, want *windowsExecutor", newExecutor())
	}
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	want := filepath.Join(programData, "cfgms", "staging")
	if !strings.EqualFold(e.tmpDir, want) {
		t.Errorf("staging base = %q, want %q", e.tmpDir, want)
	}
	if isUnder(e.tmpDir, os.TempDir()) {
		t.Errorf("staging base %q is under the system temporary directory %q", e.tmpDir, os.TempDir())
	}
	if e.addStore == nil {
		t.Error("newExecutor left addStore unset")
	}
}

func TestWindowsStagingBase_FallsBackWithoutProgramData(t *testing.T) {
	t.Setenv("ProgramData", "")
	if got, want := windowsStagingBase(), `C:\ProgramData\cfgms\staging`; got != want {
		t.Errorf("windowsStagingBase() = %q, want %q", got, want)
	}
}

// assertOnlyEntries fails t unless dir holds exactly the named entries.
func assertOnlyEntries(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != strings.Join(names, ",") {
		t.Errorf("%s holds %v, want %v", dir, got, names)
	}
}
