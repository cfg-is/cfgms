// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package hyperv

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules"
)

// Declarative checkpoint lifecycle (#2627). This file implements the reconcile-
// via-MERGE half of the checkpoint policy declared on a VMConfig (see
// CheckpointPolicy in vm.go). Cleanup MERGES stray checkpoints —
// Remove-VMSnapshot folds a checkpoint's differencing disk (.avhdx) into its
// parent, committing that data upward. It is NON-DESTRUCTIVE to the VM's current
// running state (the active disk above the chain is untouched); it never reverts.
// Restore-VMSnapshot (revert, destructive) is deliberately out of scope and never
// issued — a guarantee asserted by TestCheckpointReconcile_NeverRestores.
//
// It builds on the observed-only checkpoint DNA from #2626 (VMConfig.CheckpointCount,
// the chain-root vhd_path resolution in psGetVM); this story adds the DESIRED side.

// psGetVMSnapshots lists a VM's checkpoints oldest-first as JSON. Only $Name
// travels via ArgumentList — never interpolated. CreationTime is normalised to a
// UTC ISO-8601 round-trip string ('o') so the Go side parses it uniformly across
// Windows PowerShell 5.1 (which otherwise serialises DateTime as "/Date(ms)/") and
// pwsh 7. An empty checkpoint set yields an empty/`[]`/`null` payload (handled by
// parseVMSnapshots).
const psGetVMSnapshots = `$snaps = @(Get-VMSnapshot -VMName $Name -ErrorAction SilentlyContinue | Sort-Object CreationTime | ForEach-Object { [pscustomobject]@{ Name = $_.Name; CreationTime = $_.CreationTime.ToUniversalTime().ToString('o') } }); ConvertTo-Json @($snaps) -Compress -Depth 3`

// psRemoveVMSnapshot MERGES a single checkpoint by name into its parent. Both
// $Name and $SnapshotName travel via ArgumentList. Remove-VMSnapshot is the
// merge primitive (Hyper-V "delete checkpoint" = merge differencing disk into
// parent) — it is NOT a revert. -ErrorAction Stop surfaces a merge failure to
// the caller rather than letting it vanish as a non-terminating error.
const psRemoveVMSnapshot = `Remove-VMSnapshot -VMName $Name -Name $SnapshotName -ErrorAction Stop`

// vmSnapshot is a parsed checkpoint: its name (the Remove-VMSnapshot selector) and
// creation time (for max/max_age retention ordering).
type vmSnapshot struct {
	Name         string
	CreationTime time.Time
}

// checkpointAction is the resolved, machine-actionable form of a CheckpointPolicy.
// observe short-circuits all transport calls (the #2626 observe-only default);
// mergeAll merges every checkpoint; otherwise the retain bounds apply.
type checkpointAction struct {
	observe  bool          // take no action (nil/empty policy)
	mergeAll bool          // merge every checkpoint (policy none, or explicit max:0)
	hasMax   bool          // a positive count bound is set
	max      int           // retain the newest max checkpoints (valid when hasMax)
	maxAge   time.Duration // retain checkpoints younger than this (0 = no age bound)
}

// resolveCheckpointAction reduces a declared policy to a checkpointAction,
// applying the equivalences documented on CheckpointPolicy: policy none (or an
// explicit max:0 with no age bound) → merge all; an unset/empty block → observe;
// a bound (max>0 and/or max_age) → retain. A malformed max_age has already been
// rejected by validate() before convergence, so parse errors here degrade to "no
// age bound" rather than failing the reconcile.
func resolveCheckpointAction(p *CheckpointPolicy) checkpointAction {
	if p == nil {
		return checkpointAction{observe: true}
	}
	pol := strings.ToLower(strings.TrimSpace(p.Policy))

	hasMax := p.Max != nil
	maxVal := 0
	if hasMax {
		maxVal = *p.Max
	}

	var age time.Duration
	if p.MaxAge != "" {
		if d, err := time.ParseDuration(p.MaxAge); err == nil && d > 0 {
			age = d
		}
	}

	// Merge all: an explicit policy none, or an explicit max:0 with no age bound
	// (policy none and max:0 are equivalent "this VM should have no checkpoints"
	// triggers).
	if pol == "none" || (hasMax && maxVal == 0 && age == 0) {
		return checkpointAction{mergeAll: true}
	}

	// A present-but-empty block (no policy, no bound) behaves like an absent one:
	// observe-only, so an accidental `checkpoints: {}` never merges everything.
	if pol != "retain" && !hasMax && age == 0 {
		return checkpointAction{observe: true}
	}

	// Retain with bound(s). A max:0 reaching here only happens alongside an age
	// bound (max:0 + max_age) — treat it as "no count cap, age bound only".
	return checkpointAction{
		hasMax: maxVal > 0,
		max:    maxVal,
		maxAge: age,
	}
}

// validate enforces the fail-closed config rules for a checkpoints block. The
// headline rule (#2627): policy retain with neither a positive max nor a max_age
// is invalid — it is indistinguishable from the observe-only default. Also
// rejects an unknown policy, a negative max, and a malformed max_age duration.
func (p *CheckpointPolicy) validate() error {
	switch strings.ToLower(strings.TrimSpace(p.Policy)) {
	case "", "none", "retain":
	default:
		return ErrInvalidCheckpointPolicy
	}
	if p.Max != nil && *p.Max < 0 {
		return ErrInvalidCheckpointPolicy
	}
	if p.MaxAge != "" {
		if _, err := time.ParseDuration(p.MaxAge); err != nil {
			return ErrInvalidCheckpointPolicy
		}
	}
	if strings.EqualFold(strings.TrimSpace(p.Policy), "retain") {
		hasCount := p.Max != nil && *p.Max > 0
		hasAge := strings.TrimSpace(p.MaxAge) != ""
		if !hasCount && !hasAge {
			return ErrInvalidCheckpointPolicy
		}
	}
	return nil
}

// checkpointsComply reports whether a VM's live checkpoint set already satisfies
// the declared policy — the signal getVM uses to decide whether to echo the
// desired `checkpoints` block (no drift) or omit it (drift → reconcile, #2627).
// Count-only policies (none / max with no max_age) are judged from the
// already-observed count with NO extra PowerShell; only a max_age bound needs the
// per-snapshot creation times, so it (and only it) issues psGetVMSnapshots.
func (m *hypervModule) checkpointsComply(ctx context.Context, hostName string, policy *CheckpointPolicy, observedCount int) (bool, error) {
	action := resolveCheckpointAction(policy)
	switch {
	case action.observe:
		return true, nil
	case action.mergeAll:
		return observedCount == 0, nil
	case action.maxAge == 0:
		// Count-only retain: compliant when within the newest-N bound (or no bound).
		if action.hasMax {
			return observedCount <= action.max, nil
		}
		return true, nil
	}
	// A max_age bound needs per-snapshot times to judge — fetch and evaluate.
	if m.transport == nil {
		return false, modules.ErrNotImplemented
	}
	output, err := m.transport.ExecutePS(ctx, psGetVMSnapshots, map[string]string{"Name": hostName})
	if err != nil {
		return false, err
	}
	snaps, err := parseVMSnapshots(output)
	if err != nil {
		return false, err
	}
	return len(checkpointsToMerge(snaps, policy, time.Now().UTC())) == 0, nil
}

// parseCheckpointPolicyMap reconstructs a *CheckpointPolicy from the generic
// executor-supplied config map (the shape VMConfig.AsMap and the executor
// produce), mirroring parseSourceMap / parseHARoleMap. Returns nil for an absent
// or entirely-empty block so the reconcile stays observe-only. max is threaded as
// *int so an explicit max:0 (merge-all) survives (the map carries the key when set).
func parseCheckpointPolicyMap(v interface{}) *CheckpointPolicy {
	m, ok := v.(map[string]interface{})
	if !ok || len(m) == 0 {
		return nil
	}
	p := &CheckpointPolicy{}
	p.Policy, _ = m["policy"].(string)
	p.MaxAge, _ = m["max_age"].(string)
	if raw, present := m["max"]; present {
		switch t := raw.(type) {
		case int:
			n := t
			p.Max = &n
		case int64:
			n := int(t)
			p.Max = &n
		case float64:
			n := int(t)
			p.Max = &n
		}
	}
	if p.Policy == "" && p.Max == nil && p.MaxAge == "" {
		return nil
	}
	return p
}

// checkpointsToMerge selects, from a VM's checkpoints, the set to MERGE under the
// policy — returned OLDEST-FIRST so the caller merges from the base of the chain
// upward. A checkpoint is RETAINED only if it satisfies every active bound: within
// the newest-N window (when max is set) AND younger than max_age (when set);
// anything violating either bound is merged. mergeAll returns all; observe-only
// returns none. Pure and time-injectable (now) so the age logic is deterministic
// in tests.
func checkpointsToMerge(snaps []vmSnapshot, policy *CheckpointPolicy, now time.Time) []vmSnapshot {
	action := resolveCheckpointAction(policy)
	if action.observe || len(snaps) == 0 {
		return nil
	}

	ordered := make([]vmSnapshot, len(snaps))
	copy(ordered, snaps)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].CreationTime.Before(ordered[j].CreationTime)
	})

	if action.mergeAll {
		return ordered
	}

	n := len(ordered)
	var merge []vmSnapshot
	for i, s := range ordered {
		retained := true
		if action.hasMax && i < n-action.max {
			retained = false // beyond the newest-N retention window
		}
		if retained && action.maxAge > 0 && now.Sub(s.CreationTime) > action.maxAge {
			retained = false // older than the max_age window
		}
		if !retained {
			merge = append(merge, s)
		}
	}
	return merge
}

// reconcileCheckpoints converges a VM's checkpoint set to its declared policy by
// MERGING the stray checkpoints (oldest-first). It is a no-op (issues no PS at
// all) when the policy is observe-only (nil/empty), preserving the #2626 default.
// Called from setVM after the power/resource reconcile of an existing VM.
func (m *hypervModule) reconcileCheckpoints(ctx context.Context, hostName string, policy *CheckpointPolicy) error {
	if resolveCheckpointAction(policy).observe {
		return nil
	}
	if m.transport == nil {
		return modules.ErrNotImplemented
	}

	output, err := m.transport.ExecutePS(ctx, psGetVMSnapshots, map[string]string{"Name": hostName})
	if err != nil {
		return fmt.Errorf("hyperv: list checkpoints for %q: %w", hostName, err)
	}
	snaps, err := parseVMSnapshots(output)
	if err != nil {
		return fmt.Errorf("hyperv: parse checkpoints for %q: %w", hostName, err)
	}

	for _, s := range checkpointsToMerge(snaps, policy, time.Now().UTC()) {
		if _, err := m.transport.ExecutePS(ctx, psRemoveVMSnapshot,
			map[string]string{"Name": hostName, "SnapshotName": s.Name}); err != nil {
			return fmt.Errorf("hyperv: merge checkpoint %q on %q: %w", s.Name, hostName, err)
		}
	}
	return nil
}

// parseVMSnapshots normalises the psGetVMSnapshots JSON payload into []vmSnapshot.
// ConvertTo-Json emits an array for 0/2+ elements and may collapse a single
// element to a bare object; an empty set yields ""/"null"/"[]". All shapes are
// handled. A checkpoint whose CreationTime fails to parse keeps a zero time
// (sorts oldest / treated as very old for max_age) rather than dropping it.
func parseVMSnapshots(output string) ([]vmSnapshot, error) {
	s := strings.TrimSpace(output)
	if s == "" || s == "null" || s == "[]" {
		return nil, nil
	}

	var arr []map[string]interface{}
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		var obj map[string]interface{}
		if err2 := json.Unmarshal([]byte(s), &obj); err2 != nil {
			return nil, fmt.Errorf("unmarshal checkpoint list: %w", err)
		}
		arr = []map[string]interface{}{obj}
	}

	var out []vmSnapshot
	for _, mp := range arr {
		name, _ := mp["Name"].(string)
		if name == "" {
			continue
		}
		var ct time.Time
		if cs, ok := mp["CreationTime"].(string); ok && cs != "" {
			if t, perr := time.Parse(time.RFC3339Nano, cs); perr == nil {
				ct = t.UTC()
			}
		}
		out = append(out, vmSnapshot{Name: name, CreationTime: ct})
	}
	return out, nil
}
