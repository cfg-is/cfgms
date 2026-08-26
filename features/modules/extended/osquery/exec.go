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
// RunQuery is the exported entry point for the RPC handler (Story #3566). The
// function is intentionally query-string-agnostic: callers are responsible for
// all catalog-ID lookup and parameter validation before constructing the query
// string. See features/steward/osquery/handler.go for the admission check.
func RunQuery(ctx context.Context, binPath, query string) ([]map[string]string, error) {
	return runQuery(ctx, binPath, query)
}

func runQuery(ctx context.Context, binPath, query string) ([]map[string]string, error) {
	// args is a fixed constant slice — query content never appears here.
	// #nosec G204 — binPath is the integrity-verified binary path returned by
	// PreExecVerifier.VerifyBeforeExec; all args are constant flag strings.
	cmd := exec.CommandContext(ctx, binPath, "--json")
	// osquery's stdin batch mode requires the statement itself to be
	// terminated with a semicolon — a trailing newline alone is NOT
	// sufficient (contrary to what this comment used to claim). Verified live
	// against the real pinned Windows binary (Issue #3570): every query in
	// this package's kindToQuery and catalog.go's ad-hoc catalog lacks a
	// trailing ";", and every one of them produced empty stdout — no error,
	// just zero bytes, which json.Unmarshal then reports as "unexpected end
	// of JSON input" — when piped with only a trailing newline. Appending ";"
	// here, once, centrally, fixes every current and future caller (the
	// curated host:* queries and the ad-hoc RPC handler alike) without
	// requiring each query string to remember the contract. A query that
	// already ends with ";" after trimming trailing whitespace is left alone
	// — a redundant ";;" is a harmless empty statement to osquery. This is a
	// plain string comparison/trim on query content already destined for
	// stdin, not command-line argument construction, so it does not touch the
	// args-injection invariant above: args stays the fixed two-element slice
	// it always was.
	//
	// io.MultiReader still separates the (possibly semicolon-terminated)
	// query from the trailing newline reader below, so the terminator and the
	// final newline remain independently auditable pieces.
	//
	// This only trims trailing whitespace before checking for ";" — a query
	// ending in a SQL line comment (e.g. "... LIMIT 10 -- note") would get the
	// ";" appended onto the commented-out line, reproducing the same silent
	// empty-stdout failure this fix exists to close. No caller in this package
	// constructs a query that way today (catalog.go's parameter admission
	// gate rejects "--" outright, so only a developer-authored query string
	// could hit this), but a query added later must not end in a line
	// comment.
	terminated := strings.TrimRight(query, " \t\r\n")
	if !strings.HasSuffix(terminated, ";") {
		terminated += ";"
	}
	cmd.Stdin = io.MultiReader(strings.NewReader(terminated), strings.NewReader("\n"))

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
