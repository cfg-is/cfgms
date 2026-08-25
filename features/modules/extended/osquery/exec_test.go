// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package osquery

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeScript writes a POSIX sh script to a temp file, marks it executable, and
// returns the path. Used to create fake osquery binaries for unit tests.
func makeScript(t *testing.T, body string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fake-osquery-*")
	if err != nil {
		t.Fatalf("create temp script: %v", err)
	}
	if _, err := f.WriteString("#!/bin/sh\n" + body); err != nil {
		t.Fatalf("write script body: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close script: %v", err)
	}
	if err := os.Chmod(f.Name(), 0o700); err != nil {
		t.Fatalf("chmod script: %v", err)
	}
	return f.Name()
}

// TestRunQuery_NoArgBuildViaSprintfOrConcat is the REQUIRED TEST for
// grep-testable banned-pattern compliance (issue #3562 AC).
//
// It verifies that exec.go contains no fmt.Sprintf or string concatenation of
// query content in a Command/CommandContext argument list. Query text passed as
// a command-line argument is visible to every other process on the host via
// ps(1) / /proc/<pid>/cmdline on Linux and Get-Process on Windows — a material
// risk once caller-supplied template parameters appear in query text (later
// stories of epic #2855).
func TestRunQuery_NoArgBuildViaSprintfOrConcat(t *testing.T) {
	src, err := os.ReadFile("exec.go")
	if err != nil {
		t.Fatalf("read exec.go: %v", err)
	}
	content := string(src)

	for _, pattern := range []string{
		`fmt.Sprintf`,
		`+ query`,
		`query +`,
	} {
		if strings.Contains(content, pattern) {
			t.Errorf("exec.go contains forbidden pattern %q — query content must never be "+
				"passed as a command-line argument (visible in ps/procfs)", pattern)
		}
	}
}

// TestRunQuery_SanitizeLogValueInErrorPath is the source-scan half of the
// REQUIRED TEST for logged stderr/error output sanitization (issue #3562 AC).
//
// osquery error text can echo back query content, which is tainted input per
// CLAUDE.md's error-value logging rule. logging.SanitizeLogValue must be
// called on stderr before it is embedded in returned errors that callers log.
func TestRunQuery_SanitizeLogValueInErrorPath(t *testing.T) {
	src, err := os.ReadFile("exec.go")
	if err != nil {
		t.Fatalf("read exec.go: %v", err)
	}
	if !strings.Contains(string(src), "logging.SanitizeLogValue") {
		t.Error("exec.go must call logging.SanitizeLogValue in the error path — " +
			"osquery stderr can echo back query content (tainted input per CLAUDE.md)")
	}
}

// TestRunQuery_MalformedJSONReturnsError is a REQUIRED TEST (issue #3562 AC)
// verifying that non-JSON osquery output produces an error, not a panic.
func TestRunQuery_MalformedJSONReturnsError(t *testing.T) {
	bin := makeScript(t, `echo "this is not valid json"`)
	_, err := runQuery(context.Background(), bin, "SELECT 1")
	if err == nil {
		t.Fatal("runQuery accepted non-JSON output — a parse error must be returned")
	}
}

// TestRunQuery_StderrSanitizedInError is the behavioral half of the REQUIRED
// TEST for logged stderr/error output sanitization (issue #3562 AC).
//
// A binary that writes tainted control characters to stderr and exits non-zero
// is used to verify that the error returned by runQuery contains sanitized
// content — no raw control characters that could cause log injection.
func TestRunQuery_StderrSanitizedInError(t *testing.T) {
	// Write control characters to a temp file via Go (avoids shell escaping
	// ambiguity) and cat it to stderr from the script.
	ctrlChars := "\x01\x02\x03"
	stderrFile := filepath.Join(t.TempDir(), "tainted_stderr.txt")
	if err := os.WriteFile(stderrFile, []byte("tainted"+ctrlChars+"stderr"), 0o600); err != nil {
		t.Fatalf("write tainted stderr file: %v", err)
	}

	bin := makeScript(t, fmt.Sprintf("cat %s >&2; exit 1", stderrFile))

	_, err := runQuery(context.Background(), bin, "SELECT 1")
	if err == nil {
		t.Fatal("runQuery should return an error when the binary exits non-zero")
	}

	errMsg := err.Error()
	for _, bad := range []string{"\x01", "\x02", "\x03"} {
		if strings.Contains(errMsg, bad) {
			t.Errorf("error message contains raw control character %q — "+
				"stderr must be sanitized via logging.SanitizeLogValue before embedding in errors", bad)
		}
	}
}

// TestRunQuery_ContextCancellationTerminatesProcess verifies that a cancelled
// context terminates the child osquery process rather than blocking forever.
//
// The script uses "exec sleep 60" so the shell replaces itself with sleep — no
// child subprocess holds the stdout pipe open after the kill, so cmd.Output()
// can return promptly when the context fires.
func TestRunQuery_ContextCancellationTerminatesProcess(t *testing.T) {
	bin := makeScript(t, `exec sleep 60`)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := runQuery(ctx, bin, "SELECT 1")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("runQuery should return an error when context deadline is exceeded")
	}
	// The process must be terminated well before the 60-second sleep completes.
	// Allow generous headroom for CI scheduling jitter.
	if elapsed > 5*time.Second {
		t.Errorf("runQuery took %v — context cancellation did not terminate the process promptly", elapsed)
	}
}

// TestRunQuery_HappyPath verifies that a valid JSON response is parsed into the
// expected row slice.
func TestRunQuery_HappyPath(t *testing.T) {
	bin := makeScript(t, `echo '[{"cpu_brand":"GenuineIntel","physical_cores":"4"}]'`)

	rows, err := runQuery(context.Background(), bin, "SELECT cpu_brand, physical_cores FROM cpu_info")
	if err != nil {
		t.Fatalf("runQuery returned unexpected error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0]["cpu_brand"] != "GenuineIntel" {
		t.Errorf("cpu_brand = %q, want %q", rows[0]["cpu_brand"], "GenuineIntel")
	}
	if rows[0]["physical_cores"] != "4" {
		t.Errorf("physical_cores = %q, want %q", rows[0]["physical_cores"], "4")
	}
}

// TestRunQuery_EmptyResultSet verifies that an empty JSON array is accepted
// without error and returns a nil/zero-length slice.
func TestRunQuery_EmptyResultSet(t *testing.T) {
	bin := makeScript(t, `echo '[]'`)

	rows, err := runQuery(context.Background(), bin, "SELECT 1 WHERE 1=0")
	if err != nil {
		t.Fatalf("runQuery returned error for empty result set: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows, got %d", len(rows))
	}
}

// TestRunQuery_QueryDeliveredViaStdin verifies that the query is written to the
// child process's stdin rather than passed as a command-line argument.
//
// A binary that reads from stdin and outputs a confirmation row is used: if the
// query were passed as a CLI argument, stdin would be empty and the script
// would output an empty array.
func TestRunQuery_QueryDeliveredViaStdin(t *testing.T) {
	bin := makeScript(t, `
if read -r line; then
    echo '[{"stdin_received":"true"}]'
else
    echo '[]'
fi`)

	rows, err := runQuery(context.Background(), bin, "SELECT 1")
	if err != nil {
		t.Fatalf("runQuery error: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("binary received no stdin input — query must be delivered via stdin, " +
			"not as a command-line argument")
	}
	if rows[0]["stdin_received"] != "true" {
		t.Errorf("stdin_received = %q, want %q", rows[0]["stdin_received"], "true")
	}
}

// TestRunQuery_MultipleRows verifies parsing of a multi-row JSON result.
func TestRunQuery_MultipleRows(t *testing.T) {
	bin := makeScript(t, `echo '[{"name":"eth0","type":"ethernet"},{"name":"lo","type":"loopback"}]'`)

	rows, err := runQuery(context.Background(), bin, "SELECT name, type FROM interface_details")
	if err != nil {
		t.Fatalf("runQuery error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	if rows[0]["name"] != "eth0" {
		t.Errorf("rows[0][name] = %q, want %q", rows[0]["name"], "eth0")
	}
	if rows[1]["name"] != "lo" {
		t.Errorf("rows[1][name] = %q, want %q", rows[1]["name"], "lo")
	}
}

// TestRunQuery_NonZeroExitReturnsError verifies that a non-zero exit code from
// the osquery binary is propagated as an error.
func TestRunQuery_NonZeroExitReturnsError(t *testing.T) {
	bin := makeScript(t, `exit 2`)

	_, err := runQuery(context.Background(), bin, "SELECT 1")
	if err == nil {
		t.Fatal("runQuery should return an error when binary exits non-zero")
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected the *exec.ExitError branch, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "osquery exited non-zero") {
		t.Errorf("error %q does not identify the non-zero-exit branch", err.Error())
	}
}

// TestRunQuery_ProcessStartFailureReturnsExecutionError exercises the
// non-*exec.ExitError branch of runQuery's error handling: the failure mode
// where cmd.Output() returns before the child process ever runs, so there is no
// exit status and no captured stderr to report.
//
// This is a distinct branch from TestRunQuery_NonZeroExitReturnsError, which
// covers a process that started and then exited non-zero. Start failures are
// reachable in production whenever the verified binary path is removed, is not
// marked executable, or points at something that is not a program — for
// example, an osquery upgrade that swaps the binary between
// PreExecVerifier.VerifyBeforeExec and the exec call.
func TestRunQuery_ProcessStartFailureReturnsExecutionError(t *testing.T) {
	dir := t.TempDir()

	// A regular file with valid script content but no execute bit. execve(2)
	// requires at least one execute bit to be set, for every user including
	// root, so this fails to start on any POSIX host regardless of test UID.
	nonExecutable := filepath.Join(dir, "not-executable")
	if err := os.WriteFile(nonExecutable, []byte("#!/bin/sh\necho '[]'\n"), 0o600); err != nil {
		t.Fatalf("write non-executable file: %v", err)
	}

	tests := []struct {
		name    string
		binPath string
		// wantIs, when non-nil, is the sentinel the returned error must wrap,
		// proving runQuery preserved the cause via %w rather than flattening it.
		wantIs error
	}{
		{
			name:    "binary_path_does_not_exist",
			binPath: filepath.Join(dir, "no-such-osqueryi"),
			wantIs:  fs.ErrNotExist,
		},
		{
			name:    "binary_not_executable",
			binPath: nonExecutable,
			wantIs:  fs.ErrPermission,
		},
		{
			name:    "binary_path_is_a_directory",
			binPath: dir,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, err := runQuery(context.Background(), tt.binPath, "SELECT 1")
			if err == nil {
				t.Fatalf("runQuery returned rows %v and no error for a binary that cannot be started", rows)
			}
			if rows != nil {
				t.Errorf("runQuery returned rows %v alongside an error; the start-failure path must return nil rows", rows)
			}

			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Fatalf("expected the start-failure branch, got an *exec.ExitError: %v", err)
			}
			if !strings.Contains(err.Error(), "osquery execution failed") {
				t.Errorf("error %q does not identify the start-failure branch — callers "+
					"distinguish a binary that never ran from one that exited non-zero", err.Error())
			}
			if strings.Contains(err.Error(), "osquery exited non-zero") {
				t.Errorf("error %q reports a non-zero exit for a process that never started", err.Error())
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("error %v does not wrap %v — the underlying cause must be "+
					"preserved with %%w so callers can inspect it", err, tt.wantIs)
			}
		})
	}
}
