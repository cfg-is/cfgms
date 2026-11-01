// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/mattn/go-isatty"
)

// fanOutConcurrencyBound caps the number of concurrent per-steward REST calls
// issued by fanOutConcurrent. Matches the batchSize default used server-side
// (handlers_jobs.go:65-67) for consistency.
const fanOutConcurrencyBound = 10

// StewardInfoDNA holds the DNA fields returned by the fleet/resolve endpoint.
// Defined as a named type so callers and tests can reference it without
// repeating the anonymous-struct literal.
type StewardInfoDNA struct {
	Hostname     string               `json:"hostname"`
	OS           string               `json:"os"`
	Architecture string               `json:"architecture"`
	Attributes   map[string]string    `json:"attributes,omitempty"`
	Fragments    []*commonpb.Fragment `json:"fragments,omitempty"`
}

// StewardInfo is the CLI's view of a steward entry returned by
// POST /api/v1/fleet/resolve. Fields match the server-side resolve response.
type StewardInfo struct {
	ID       string          `json:"id"`
	Status   string          `json:"status"`
	LastSeen time.Time       `json:"last_seen"`
	Version  string          `json:"version"`
	TenantID string          `json:"tenant_id,omitempty"`
	DNA      *StewardInfoDNA `json:"dna,omitempty"`
}

// stewardKey returns the unambiguous per-steward output key used as the JSON
// object key in keyed output and as the map key in fanOutConcurrent results.
//
// Format: "<hostname>#<steward-id>"
// Hostname (from DNA) makes the key human-readable; the steward-id suffix
// ensures uniqueness even when two stewards share a hostname. When DNA is
// absent or Hostname is empty the key is "#<steward-id>".
func stewardKey(s StewardInfo) string {
	hostname := ""
	if s.DNA != nil {
		hostname = s.DNA.Hostname
	}
	return hostname + "#" + s.ID
}

// resolveOrFailFast calls ResolveSelector and returns a clear error when
// the selector matches zero stewards. All multi-host verbs must call this
// instead of ResolveSelector directly so the 0-match behaviour lives in
// exactly one place.
func resolveOrFailFast(ctx context.Context, client *APIClient, selector string) ([]StewardInfo, error) {
	matches, err := client.ResolveSelector(ctx, selector)
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("selector %q matched no stewards", selector)
	}
	return matches, nil
}

// confirmMultiHost enforces the --yes gate for mutating multi-host verbs.
//
// Rules (A4):
//   - 0 or 1 matches: no-op (single-host ops never need confirmation).
//   - N>1 + yes=true: proceeds without prompting (on any terminal).
//   - N>1 + yes=false + non-interactive stdin: fails closed with a clear error.
//   - N>1 + yes=false + interactive TTY: prompts interactively.
//
// This function never suppresses the 0-match fail-fast error; callers must
// call resolveOrFailFast before confirmMultiHost.
func confirmMultiHost(matches []StewardInfo, yes bool) error {
	if len(matches) <= 1 {
		return nil
	}

	tenantSet := make(map[string]struct{})
	for _, m := range matches {
		if m.TenantID != "" {
			tenantSet[m.TenantID] = struct{}{}
		}
	}

	if len(tenantSet) > 0 {
		fmt.Fprintf(os.Stderr, "matched %d stewards across %d tenant(s):\n", len(matches), len(tenantSet))
	} else {
		fmt.Fprintf(os.Stderr, "matched %d stewards:\n", len(matches))
	}
	for _, m := range matches {
		key := stewardKey(m)
		if m.TenantID != "" {
			fmt.Fprintf(os.Stderr, "  %s (tenant: %s)\n", key, m.TenantID)
		} else {
			fmt.Fprintf(os.Stderr, "  %s\n", key)
		}
	}

	if yes {
		return nil
	}

	// Non-interactive stdin: fail closed — never block on a hidden pipe.
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return fmt.Errorf("operation targets %d stewards; pass --yes/-y to confirm, or run interactively", len(matches))
	}

	// Interactive: prompt the operator.
	fmt.Fprint(os.Stderr, "Proceed? [y/N]: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if answer == "y" || answer == "yes" {
			return nil
		}
	}
	return fmt.Errorf("aborted by operator")
}

// fanOutResult holds the outcome of a single per-steward action invocation.
// The explicit Success field allows callers to distinguish a nil payload
// (successful call with no data) from a failed call.
type fanOutResult struct {
	Success bool
	Payload json.RawMessage
	Err     error
}

// fanOutConcurrent runs action for every steward in matches with at most
// fanOutConcurrencyBound (10) concurrent in-flight calls. Results are keyed
// by stewardKey. A non-nil overallErr is returned when any single steward's
// action failed; the owning cobra RunE should return this error so the process
// exits non-zero on any partial failure.
//
// Used by verbs that issue per-steward REST calls client-side (status, dna,
// logs, modules, move, decommission — stories 7 and 8). Verbs that dispatch
// server-side fan-out (exec, run-script, run-command, upgrade) do not call
// this — they use the resolve/confirm helpers only.
func fanOutConcurrent(
	ctx context.Context,
	matches []StewardInfo,
	action func(context.Context, StewardInfo) (json.RawMessage, error),
) (map[string]fanOutResult, error) {
	sem := make(chan struct{}, fanOutConcurrencyBound)
	var mu sync.Mutex
	results := make(map[string]fanOutResult, len(matches))

	var wg sync.WaitGroup
	for _, m := range matches {
		m := m
		key := stewardKey(m)
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			payload, err := action(ctx, m)
			mu.Lock()
			results[key] = fanOutResult{
				Success: err == nil,
				Payload: payload,
				Err:     err,
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	var overallErr error
	for _, r := range results {
		if r.Err != nil {
			overallErr = fmt.Errorf("one or more steward actions failed")
			break
		}
	}
	return results, overallErr
}

// KeyedOutputEntry is a single row in the keyed JSON output produced by
// keyedOutput. The Success field is always present so partial failures are
// representable in both human and --json output.
type KeyedOutputEntry struct {
	Key     string          `json:"key"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// emitKeyedDispatchOutput writes a keyed-by-steward JSON array to stdout
// where every matched steward receives the same payload. Used by run-script,
// run-command, and upgrade --json, where the server fans out to all matches
// under a single run/upgrade ID rather than issuing per-steward REST calls.
func emitKeyedDispatchOutput(matches []StewardInfo, payload map[string]interface{}) error {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	perStewardResult := make(map[string]fanOutResult, len(matches))
	for _, m := range matches {
		perStewardResult[stewardKey(m)] = fanOutResult{
			Success: true,
			Payload: payloadJSON,
		}
	}
	entries := keyedOutput(matches, perStewardResult)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

// keyedOutput builds the keyed-by-steward output slice consumed by --json
// and the human host-prefix output. Entries are in the same order as matches
// for deterministic output. Each entry carries an explicit success/failure
// status so partial failures survive JSON serialisation.
func keyedOutput(matches []StewardInfo, perStewardResult map[string]fanOutResult) []KeyedOutputEntry {
	out := make([]KeyedOutputEntry, 0, len(matches))
	for _, m := range matches {
		key := stewardKey(m)
		r := perStewardResult[key]
		entry := KeyedOutputEntry{
			Key:     key,
			Success: r.Success,
			Payload: r.Payload,
		}
		if r.Err != nil {
			entry.Error = r.Err.Error()
		}
		out = append(out, entry)
	}
	return out
}
