// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ── Declarative VM storage location (#2411) ───────────────────────────────────
//
// The directory containing the declared vhd_path is the VM's home: the VM's
// configuration files AND its virtual disk both belong there. Creation places
// everything at the home (New-VM -Path + a config-only Move-VMStorage, because
// New-VM unconditionally appends a VM-name subfolder to -Path — verified live
// on cfg-lab 2026-07-07). Location drift on an existing VM converges via a
// live, non-destructive Move-VMStorage.
//
// The converge move is ASYNC: the executor's per-module-call deadline
// (ADR-012 §7) would kill a multi-minute storage migration mid-flight, so the
// module dispatches the migration as a detached PowerShell process and tracks
// it through a durable MoveRecord (#2371 record machinery). Converge cycles
// that observe an in-flight record are cheap no-ops; completion is judged by
// re-observing the location, never by parsing migration-job objects.
//
// Location convergence is DIRECTORY-level: Move-VMStorage silently ignores a
// -Vhds destination whose only difference is the file name (verified live), so
// renaming a VHD via vhd_path is not supported — only its directory converges.

// ── Provisioning PS verb constants ────────────────────────────────────────────
//
// Like the ADR-009 §5 provisioning verbs in vm_provision.go, these are
// platform-neutral dispatch keys: the Windows ps-host transport
// (pstransport_dispatch_windows.go) pattern-matches them to their Cfgms-*
// preamble functions; the recording transport in tests records them verbatim.
// All user-controlled values travel via PS function parameters — never
// interpolated into script text.
const (
	// psSetVMHome homes a VM's configuration files (config + checkpoints +
	// smart paging, NOT disks) at exactly $Home via a synchronous config-only
	// Move-VMStorage. Used at create time, where the config files are KB-scale
	// and the move completes well within the module-call deadline.
	psSetVMHome = `Cfgms-SetVMHome`

	// psVMStorageMovePreflight reports the bytes required to move the VM's
	// disks into $DestDir vs the free bytes on the destination volume, as JSON
	// {"required_bytes":N,"free_bytes":M}. free_bytes is -1 when the
	// destination volume cannot be resolved.
	psVMStorageMovePreflight = `Cfgms-VMStorageMovePreflight`

	// psMoveVMStorage dispatches the full live storage migration (config +
	// checkpoints + smart paging + all attached disks, each landing at
	// $Home\<its current leaf> — directory-level; Hyper-V refuses file-name
	// changes in a move) as a DETACHED process. The module call returns as
	// soon as the migration process has started; the MoveRecord is the source
	// of truth for "started".
	psMoveVMStorage = `Cfgms-MoveVMStorage`

	// psGetVMMoveError reads the error marker the detached migration writes on
	// failure, as JSON {"error":"..."} ("" when no failure is recorded).
	psGetVMMoveError = `Cfgms-GetVMMoveError`

	// psClearVMMoveError removes a stale error marker before a (re)dispatch so
	// a prior failure is never misattributed to the new attempt.
	psClearVMMoveError = `Cfgms-ClearVMMoveError`
)

// moveStallTimeout bounds how long an in-flight move record is trusted without
// observable completion or a surfaced error. A move interrupted by a host
// reboot leaves the VM at its original location (Hyper-V semantics) with no
// error marker; once StartedAt is older than this bound the record is failed
// loudly and the next converge may retry. Sized for multi-hundred-GB disks on
// spinning storage; lab-scale moves complete in minutes.
const moveStallTimeout = 4 * time.Hour

// MoveState is the lifecycle position of an async VM storage migration.
type MoveState string

const (
	// MoveStateMoving marks a dispatched, in-flight storage migration.
	MoveStateMoving MoveState = "moving"
	// MoveStateFailed marks a migration that failed (preflight, dispatch, or
	// surfaced error) — the next converge cycle may retry, bounded to one
	// attempt per cycle.
	MoveStateFailed MoveState = "failed"
)

// ErrMoveNotFound is returned when no move record exists for a VM.
var ErrMoveNotFound = errors.New("hyperv: move record not found")

// MoveRecord tracks an in-flight (or failed) storage-location migration for a
// VM. It is JSON-serialisable and persisted through the durable record store
// (#2371) so a move in flight across a steward restart is re-observed, never
// re-dispatched blindly.
type MoveRecord struct {
	VMName    string    `json:"vm_name"`
	State     MoveState `json:"state"`
	DestDir   string    `json:"dest_dir"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
	LastError string    `json:"last_error,omitempty"`
}

// MoveStore is the persistence surface for VM storage-move records. Both
// in-repo ProvisionStore implementations (in-memory and flatfile-durable)
// implement it; move records live in a keyspace separate from provision
// records so the two lifecycles never collide.
type MoveStore interface {
	GetMove(ctx context.Context, vmName string) (*MoveRecord, error)
	SetMove(ctx context.Context, record *MoveRecord) error
	DeleteMove(ctx context.Context, vmName string) error
}

// moveStore returns the MoveStore backing this module: the provision store
// when it implements MoveStore (both in-repo stores do — the factory-wired
// flatfile store makes records durable), else a module-local in-memory
// fallback so a custom ProvisionStore cannot panic the move path.
func (m *hypervModule) moveStore() MoveStore {
	if m.provisionStore == nil {
		m.provisionStore = NewMemProvisionStore()
	}
	if ms, ok := m.provisionStore.(MoveStore); ok {
		return ms
	}
	if m.fallbackMoveStore == nil {
		m.fallbackMoveStore = NewMemProvisionStore()
	}
	return m.fallbackMoveStore
}

// vmHomeDir returns the directory containing a declared vhd_path — the VM's
// home. Computed with Windows path semantics (split on \ or /) rather than
// filepath.Dir, which mangles always-Windows Hyper-V paths on a non-Windows
// steward or CI host (same rationale as seedVHDPath, Issue #2044). Returns ""
// when the path has no directory component.
func vmHomeDir(vhdPath string) string {
	i := strings.LastIndexAny(vhdPath, `\/`)
	if i < 0 {
		return ""
	}
	return strings.TrimRight(vhdPath[:i], `\/`)
}

// sameWindowsPath reports whether two Windows paths refer to the same
// location: case-insensitive, separator-insensitive (\ vs /), trailing
// separators ignored. Empty paths never match anything.
func sameWindowsPath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	norm := func(p string) string {
		p = strings.ReplaceAll(p, "/", `\`)
		return strings.TrimRight(p, `\`)
	}
	return strings.EqualFold(norm(a), norm(b))
}

// storageLocationDrift reports whether the observed VM state has its storage
// outside the declared home directory: the configuration-file location (when
// the host reports one) or the primary disk's directory differing from home is
// drift. home == "" (no vhd_path declared) never drifts.
func storageLocationDrift(current *VMConfig, home string) bool {
	if home == "" {
		return false
	}
	if current.ConfigLocation != "" && !sameWindowsPath(current.ConfigLocation, home) {
		return true
	}
	if current.VHDPath != "" && !sameWindowsPath(vmHomeDir(current.VHDPath), home) {
		return true
	}
	return false
}

// convergeStorageLocation drives the declarative storage-location convergence
// for an existing VM. Returns proceed=true when the rest of the apply cycle
// (network, ha_role, power state) should continue — i.e. the location is
// converged. When a move is started or in flight it returns proceed=false so
// the cycle defers everything else (an ha_role registration on a mislocated VM
// fails; power transitions resume once the location converges).
//
// The decision tree, per converge cycle:
//
//	no drift            → clear any lingering record; proceed.
//	drift + no record   → preflight, dispatch detached move, record moving.
//	drift + moving      → completed-at-old-dest → clear record, start new move;
//	                      error marker surfaced → record failed, loud error;
//	                      stalled past moveStallTimeout → record failed, loud;
//	                      otherwise → cheap no-op (never a duplicate dispatch).
//	drift + failed      → retry: one new attempt this cycle.
func (m *hypervModule) convergeStorageLocation(ctx context.Context, vmName, hostName string, desired, current *VMConfig) (bool, error) {
	home := vmHomeDir(desired.VHDPath)
	if home == "" {
		return true, nil
	}

	store := m.moveStore()
	record, err := store.GetMove(ctx, vmName)
	if err != nil && !errors.Is(err, ErrMoveNotFound) {
		return false, fmt.Errorf("hyperv: read move record for VM %q: %w", vmName, err)
	}
	if errors.Is(err, ErrMoveNotFound) {
		record = nil
	}

	if !storageLocationDrift(current, home) {
		// Converged. A lingering record (the move that produced this state, or
		// one obsoleted by a config change) is complete — clear it.
		if record != nil {
			if dErr := store.DeleteMove(ctx, vmName); dErr != nil && !errors.Is(dErr, ErrMoveNotFound) {
				return false, fmt.Errorf("hyperv: clear completed move record for VM %q: %w", vmName, dErr)
			}
			if logger, ok := m.GetLogger(); ok {
				logger.Info("hyperv: storage move complete; VM at declared home",
					"vm_name", logging.SanitizeLogValue(vmName),
					"home", logging.SanitizeLogValue(home))
			}
		}
		return true, nil
	}

	if record != nil && record.State == MoveStateMoving {
		// The declared home may have changed while a previous move was in
		// flight: a VM observed at the RECORDED destination means that move
		// completed — clear it and start the move to the new home below.
		if !storageLocationDrift(current, record.DestDir) {
			if dErr := store.DeleteMove(ctx, vmName); dErr != nil && !errors.Is(dErr, ErrMoveNotFound) {
				return false, fmt.Errorf("hyperv: clear superseded move record for VM %q: %w", vmName, dErr)
			}
			record = nil
		} else {
			// In flight. Surface a failure the detached migration recorded;
			// otherwise this cycle is a cheap no-op — never a second dispatch.
			moveErr, pErr := m.probeMoveError(ctx, hostName)
			if pErr != nil {
				return false, pErr
			}
			if moveErr != "" {
				return false, m.failMove(ctx, vmName, record, fmt.Errorf("hyperv: storage move for VM %q failed: %s", vmName, moveErr))
			}
			if time.Since(record.StartedAt) > moveStallTimeout {
				return false, m.failMove(ctx, vmName, record, fmt.Errorf(
					"hyperv: storage move for VM %q did not complete within %s (interrupted move leaves the VM at its original location); will retry", vmName, moveStallTimeout))
			}
			if logger, ok := m.GetLogger(); ok {
				logger.Info("hyperv: storage move in flight; waiting (no duplicate dispatch)",
					"vm_name", logging.SanitizeLogValue(vmName),
					"dest", logging.SanitizeLogValue(record.DestDir))
			}
			return false, nil
		}
	}

	// Drift with no in-flight record (fresh, failed-retry, or superseded):
	// one attempt this cycle. Preflight the destination's free space BEFORE
	// dispatching — a move that cannot fit must fail loudly without starting.
	required, free, pfErr := m.moveSpacePreflight(ctx, hostName, home)
	if pfErr != nil {
		return false, m.failMove(ctx, vmName, ensureMoveRecord(record, vmName, home), pfErr)
	}
	if free >= 0 && free < required {
		return false, m.failMove(ctx, vmName, ensureMoveRecord(record, vmName, home), fmt.Errorf(
			"hyperv: insufficient space on destination volume for VM %q storage move: need %d bytes, %d free at %q", vmName, required, free, home))
	}

	// Clear any stale error marker so a prior failure is never misattributed
	// to this attempt, then dispatch the detached live migration.
	if _, psErr := m.transport.ExecutePS(ctx, psClearVMMoveError, map[string]string{"Name": hostName}); psErr != nil {
		return false, m.failMove(ctx, vmName, ensureMoveRecord(record, vmName, home), fmt.Errorf("hyperv: clear move error marker for VM %q: %w", vmName, psErr))
	}
	before := map[string]interface{}{"configuration_location": current.ConfigLocation}
	after := map[string]interface{}{"configuration_location": home}
	_, psErr := m.transport.ExecutePS(ctx, psMoveVMStorage, map[string]string{
		"Name": hostName,
		"Home": home,
	})
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Move-VMStorage", "vm:"+vmName, before, after, psErr)
	if psErr != nil {
		return false, m.failMove(ctx, vmName, ensureMoveRecord(record, vmName, home), fmt.Errorf("hyperv: dispatch storage move for VM %q: %w", vmName, psErr))
	}

	now := time.Now().UTC()
	newRecord := &MoveRecord{
		VMName:    vmName,
		State:     MoveStateMoving,
		DestDir:   home,
		StartedAt: now,
		UpdatedAt: now,
	}
	if sErr := store.SetMove(ctx, newRecord); sErr != nil {
		return false, fmt.Errorf("hyperv: persist move record for VM %q: %w", vmName, sErr)
	}
	if logger, ok := m.GetLogger(); ok {
		logger.Info("hyperv: live storage move dispatched",
			"vm_name", logging.SanitizeLogValue(vmName),
			"home", logging.SanitizeLogValue(home))
	}
	return false, nil
}

// ensureMoveRecord returns the existing record, or a fresh one for vmName →
// destDir when none exists yet, so failures before the first dispatch still
// land on a record.
func ensureMoveRecord(record *MoveRecord, vmName, destDir string) *MoveRecord {
	if record != nil {
		return record
	}
	now := time.Now().UTC()
	return &MoveRecord{
		VMName:    vmName,
		State:     MoveStateFailed,
		DestDir:   destDir,
		StartedAt: now,
		UpdatedAt: now,
	}
}

// failMove records the failure on the move record (state=failed, LastError
// set), persists it, emits a structured log event, and returns the cause so
// the caller surfaces it loudly.
func (m *hypervModule) failMove(ctx context.Context, vmName string, record *MoveRecord, cause error) error {
	record.State = MoveStateFailed
	record.UpdatedAt = time.Now().UTC()
	if cause != nil {
		record.LastError = cause.Error()
	}
	// Persist best-effort; the original cause is the error we surface.
	_ = m.moveStore().SetMove(ctx, record)
	if logger, ok := m.GetLogger(); ok {
		logger.Warn("hyperv: storage move failed",
			"vm_name", logging.SanitizeLogValue(vmName),
			"dest", logging.SanitizeLogValue(record.DestDir))
	}
	return cause
}

// moveSpacePreflight asks the host how many bytes the VM's disks require at
// destDir vs the destination volume's free bytes. free == -1 means the volume
// could not be resolved; the caller proceeds (the move itself surfaces a real
// failure) rather than blocking on a probe gap.
func (m *hypervModule) moveSpacePreflight(ctx context.Context, hostName, destDir string) (required, free int64, err error) {
	output, psErr := m.transport.ExecutePS(ctx, psVMStorageMovePreflight, map[string]string{
		"Name":    hostName,
		"DestDir": destDir,
	})
	if psErr != nil {
		return 0, 0, fmt.Errorf("hyperv: storage move preflight for VM %q: %w", hostName, psErr)
	}
	var parsed struct {
		RequiredBytes int64 `json:"required_bytes"`
		FreeBytes     int64 `json:"free_bytes"`
	}
	if jErr := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); jErr != nil {
		return 0, 0, fmt.Errorf("hyperv: parse storage move preflight for VM %q: %w", hostName, jErr)
	}
	return parsed.RequiredBytes, parsed.FreeBytes, nil
}

// probeMoveError reads the error marker the detached migration process writes
// on failure. An empty string means no failure has been recorded.
func (m *hypervModule) probeMoveError(ctx context.Context, hostName string) (string, error) {
	output, psErr := m.transport.ExecutePS(ctx, psGetVMMoveError, map[string]string{"Name": hostName})
	if psErr != nil {
		return "", fmt.Errorf("hyperv: probe move error for VM %q: %w", hostName, psErr)
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if jErr := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); jErr != nil {
		return "", fmt.Errorf("hyperv: parse move error probe for VM %q: %w", hostName, jErr)
	}
	return strings.TrimSpace(parsed.Error), nil
}

// execSetVMHome homes a freshly created VM's configuration files at exactly
// home via a synchronous config-only Move-VMStorage (New-VM -Path appends a
// VM-name subfolder, so the create path always follows with this move; the
// files are KB-scale and complete well within the module-call deadline).
func (m *hypervModule) execSetVMHome(ctx context.Context, cfgResourceID, hostName, home string) error {
	_, psErr := m.transport.ExecutePS(ctx, psSetVMHome, map[string]string{
		"Name": hostName,
		"Home": home,
	})
	after := map[string]interface{}{"configuration_location": home}
	recordHypervOp(ctx, m.auditMgr, m.tenantID, m.stewardID, m.host, "Move-VMStorage", cfgResourceID, nil, after, psErr)
	if psErr != nil {
		return fmt.Errorf("hyperv: home configuration files for VM %q at %q: %w", hostName, home, psErr)
	}
	return nil
}

// ── MoveStore implementations ─────────────────────────────────────────────────

// GetMove implements MoveStore for the in-memory store.
func (s *memProvisionStore) GetMove(_ context.Context, vmName string) (*MoveRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.moves[vmName]
	if !ok {
		return nil, ErrMoveNotFound
	}
	cp := *r
	return &cp, nil
}

// SetMove implements MoveStore for the in-memory store.
func (s *memProvisionStore) SetMove(_ context.Context, record *MoveRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *record
	s.moves[record.VMName] = &cp
	return nil
}

// DeleteMove implements MoveStore for the in-memory store.
func (s *memProvisionStore) DeleteMove(_ context.Context, vmName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.moves[vmName]; !ok {
		return ErrMoveNotFound
	}
	delete(s.moves, vmName)
	return nil
}

// moveNamespace is the stored-config namespace for hyperv move records —
// separate from provisionNamespace so the two record lifecycles never collide.
// Dash separator (not slash) for keysafe path-safety compliance.
const moveNamespace = "hyperv-moves"

func (s *ConfigBackedProvisionStore) moveKey(vmName string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{
		TenantID:  s.tenantID,
		Namespace: moveNamespace,
		Name:      vmName,
	}
}

// GetMove implements MoveStore for the durable config-backed store.
func (s *ConfigBackedProvisionStore) GetMove(ctx context.Context, vmName string) (*MoveRecord, error) {
	entry, err := s.store.GetConfig(ctx, s.moveKey(vmName))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return nil, ErrMoveNotFound
		}
		return nil, fmt.Errorf("hyperv: get move record %q: %w", vmName, err)
	}
	var record MoveRecord
	if err := json.Unmarshal(entry.Data, &record); err != nil {
		return nil, fmt.Errorf("hyperv: decode move record %q: %w", vmName, err)
	}
	return &record, nil
}

// SetMove implements MoveStore for the durable config-backed store.
func (s *ConfigBackedProvisionStore) SetMove(ctx context.Context, record *MoveRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("hyperv: encode move record %q: %w", record.VMName, err)
	}
	return s.store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:    s.moveKey(record.VMName),
		Data:   data,
		Format: cfgconfig.ConfigFormatJSON,
	})
}

// DeleteMove implements MoveStore for the durable config-backed store.
func (s *ConfigBackedProvisionStore) DeleteMove(ctx context.Context, vmName string) error {
	err := s.store.DeleteConfig(ctx, s.moveKey(vmName))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return ErrMoveNotFound
		}
		return fmt.Errorf("hyperv: delete move record %q: %w", vmName, err)
	}
	return nil
}

// Verify both in-repo stores satisfy the MoveStore contract.
var (
	_ MoveStore = (*memProvisionStore)(nil)
	_ MoveStore = (*ConfigBackedProvisionStore)(nil)
)
