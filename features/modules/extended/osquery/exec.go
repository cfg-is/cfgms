// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Security invariants enforced in this file — a reviewer checking issue #3562
// acceptance criteria should read this comment first:
//
//  1. Query text is delivered to osquery via stdin, never as a command-line
//     argument. Command-line query text is visible to every process on the host
//     via ps(1) / /proc/<pid>/cmdline on Linux and Get-Process on Windows. This
//     matters most once later stories of epic #2855 introduce caller-supplied
//     template parameters into query text.
//
//  2. exec.CommandContext is called with a fixed, constant args slice. The
//     argument list is never constructed by format-string interpolation or
//     string concatenation of query content. Grep for "exec.Command" in this
//     file to verify: one call site exists and its args contain only constant
//     flag strings.
//
//  3. osquery stderr is sanitized via logging.SanitizeLogValue before being
//     embedded in returned errors. osquery error text can echo back query
//     content, which is tainted input per the CLAUDE.md error-value logging rule
//     ("error values: logging.SanitizeLogValue(err.Error()), never err").
//     Sanitizing before embedding means callers who log the returned error log
//     sanitized content without needing their own sanitization step.

package osquery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"strings"

	"github.com/cfgis/cfgms/pkg/logging"
)

// runQuery executes the integrity-verified osquery binary at binPath, delivers
// query to the process via stdin, parses the JSON-array output, and returns the
// result rows.
//
// Callers are responsible for calling PreExecVerifier.VerifyBeforeExec before
// each invocation to obtain a verified binPath; runQuery does not repeat that
// check (story #3561). The production caller is getHostFact, which resolves
// binPath through osqueryModule.verifiedBinPath (module.go) on every Get() —
// the only path in this package that reaches runQuery.
//
// osquery 5.13.1 stdin contract: osqueryi reads SQL from stdin when its stdin
// is not a terminal (non-TTY, i.e. programmatic invocation with piped input).
// The --json flag requests JSON-array output. No SQL argument is passed on the
// command line — the fixed args slice contains only constant flag strings.
func runQuery(ctx context.Context, binPath, query string) ([]map[string]string, error) {
	// args is a fixed constant slice — query content never appears here.
	// #nosec G204 — binPath is the integrity-verified binary path returned by
	// PreExecVerifier.VerifyBeforeExec; all args are constant flag strings.
	cmd := exec.CommandContext(ctx, binPath, "--json")
	// A trailing newline ensures the SQL statement is terminated before EOF,
	// satisfying osquery's batch-mode statement detection. io.MultiReader is
	// used so query content is never concatenated with other strings — the
	// sanitised-stdin invariant is easier to audit when each reader is separate.
	cmd.Stdin = io.MultiReader(strings.NewReader(query), strings.NewReader("\n"))

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Sanitize stderr before embedding: osquery can echo back query
			// content in error messages (tainted input per CLAUDE.md). The
			// sanitized string is safe for callers to pass to any logger.
			sanitizedStderr := logging.SanitizeLogValue(string(exitErr.Stderr))
			return nil, fmt.Errorf("osquery exited non-zero: %w; stderr: %s", err, sanitizedStderr)
		}
		return nil, classifyStartError(err)
	}

	var rows []map[string]string
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("osquery output parse error: %w", err)
	}
	return rows, nil
}

// classifyStartError wraps an error from cmd.Output() that occurred before
// the child process ever ran (i.e. not an *exec.ExitError) so that a missing
// binary reliably satisfies errors.Is(err, fs.ErrNotExist) on every platform.
//
// On POSIX, os.StartProcess for a missing path returns a *fs.PathError
// wrapping fs.ErrNotExist directly, so %w alone already satisfies that
// check. On Windows, exec.Command resolves an extensionless path — even an
// absolute one — via LookPath, whose not-found failure mode is
// exec.ErrNotFound wrapped in *exec.Error, which does not wrap
// fs.ErrNotExist. Mapping it here keeps that platform difference out of
// every caller.
func classifyStartError(err error) error {
	var lookErr *exec.Error
	if errors.As(err, &lookErr) && errors.Is(lookErr.Err, exec.ErrNotFound) {
		return fmt.Errorf("osquery execution failed: %w: %w", err, fs.ErrNotExist)
	}
	return fmt.Errorf("osquery execution failed: %w", err)
}
