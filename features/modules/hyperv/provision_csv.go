// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// csvProvisionSubdir is the directory (under a VM's home dir) that holds the
// cluster-visible provisioning records. A leading dot keeps it out of the way of
// the VM's own files on the CSV.
const csvProvisionSubdir = ".cfgms-provision"

// csvProvisionStore is a ProvisionStore that persists each ProvisionRecord as
// JSON on the same Cluster Shared Volume as the VM's primary VHD, at
// <homeDir>/.cfgms-provision/<vm_name>.json. Because the CSV is mounted on every
// member node, the record is readable from any node — so after a CNO failover
// mid-provision the new owner reads the in-progress record and surfaces-and-waits
// (ADR-009 Amendment 1 A1.4, Option A) instead of creating a duplicate VM.
//
// homeDir is dir(vhd_path), computed by the caller via vmHomeDir (NOT
// filepath.Dir, which mangles an always-Windows vhd_path on the Linux CI host —
// Issue #2044). Within the store, filepath.Join/os are OS-native: in production
// homeDir is a real Windows CSV path on the Windows steward; in tests it is a
// real local temp dir — filepath.Join is correct for both.
type csvProvisionStore struct {
	homeDir string
}

// newCSVProvisionStore returns a store rooted at a VM's home directory. Path
// validity is checked lazily at each operation (fail-loud on use) rather than at
// construction, because storeFor returns a ProvisionStore without an error path.
func newCSVProvisionStore(homeDir string) *csvProvisionStore {
	return &csvProvisionStore{homeDir: homeDir}
}

// recordDir returns <homeDir>/.cfgms-provision, rejecting an empty or UNC home
// dir (the record must live on a local/CSV drive next to the VHD, never on an
// arbitrary network share — same invariant as ErrInvalidSeedPath) AND any homeDir
// containing a ".." segment. The ".." guard is load-bearing, not cosmetic:
// vmHomeDir does not Clean the path and vhdPathPattern permits "..", so a
// vhd_path like C:\ClusterStorage\Vol1\..\..\Windows\x.vhdx passes isUnderCSV
// (raw prefix match) yet filepath.Join would Clean it to an off-CSV location —
// silently defeating the cluster-visibility invariant this store exists to
// provide (the record would land host-local, invisible to a post-failover owner).
func (s *csvProvisionStore) recordDir() (string, error) {
	if s.homeDir == "" || strings.HasPrefix(s.homeDir, `\\`) || strings.HasPrefix(s.homeDir, `//`) {
		return "", ErrInvalidSeedPath
	}
	for _, seg := range strings.FieldsFunc(s.homeDir, func(r rune) bool { return r == '\\' || r == '/' }) {
		if seg == ".." {
			return "", ErrInvalidSeedPath
		}
	}
	return filepath.Join(s.homeDir, csvProvisionSubdir), nil
}

// recordPath returns the JSON path for a VM's record, guarding vmName against
// path traversal / separator injection (it becomes a filename).
func (s *csvProvisionStore) recordPath(vmName string) (string, error) {
	dir, err := s.recordDir()
	if err != nil {
		return "", err
	}
	if vmName == "" || strings.ContainsAny(vmName, `\/`) || strings.Contains(vmName, "..") {
		return "", ErrInvalidSeedPath
	}
	return filepath.Join(dir, vmName+".json"), nil
}

func (s *csvProvisionStore) GetProvision(_ context.Context, vmName string) (*ProvisionRecord, error) {
	path, err := s.recordPath(vmName)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrProvisionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("hyperv: read provision record %q: %w", vmName, err)
	}
	var rec ProvisionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("hyperv: parse provision record %q: %w", vmName, err)
	}
	// rec is already a local copy; return its address (copy-on-read).
	return &rec, nil
}

// SetProvision writes the record crash-safely: a temp file in the same directory
// is fully written, then os.Rename'd over the final path. A CNO failover reading
// the record mid-write therefore observes either the old record or the new one,
// never a truncated one — the store must not introduce the very partial-write
// window Option A exists to close.
func (s *csvProvisionStore) SetProvision(_ context.Context, record *ProvisionRecord) error {
	dir, err := s.recordDir()
	if err != nil {
		return err
	}
	path, err := s.recordPath(record.VMName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("hyperv: create provision dir: %w", err)
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("hyperv: encode provision record %q: %w", record.VMName, err)
	}
	tmp, err := os.CreateTemp(dir, "."+record.VMName+".*.tmp")
	if err != nil {
		return fmt.Errorf("hyperv: create temp provision record %q: %w", record.VMName, err)
	}
	tmpName := tmp.Name()
	if _, werr := tmp.Write(data); werr != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("hyperv: write provision record %q: %w", record.VMName, werr)
	}
	if cerr := tmp.Close(); cerr != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("hyperv: close provision record %q: %w", record.VMName, cerr)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("hyperv: commit provision record %q: %w", record.VMName, err)
	}
	return nil
}

func (s *csvProvisionStore) DeleteProvision(_ context.Context, vmName string) error {
	path, err := s.recordPath(vmName)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrProvisionNotFound
		}
		return fmt.Errorf("hyperv: delete provision record %q: %w", vmName, err)
	}
	return nil
}

// ListProvisions returns snapshot copies of every record in the store's
// directory. A missing directory (no VM ever provisioned here) is an empty list,
// not an error.
func (s *csvProvisionStore) ListProvisions(_ context.Context) ([]*ProvisionRecord, error) {
	dir, err := s.recordDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("hyperv: list provision records: %w", err)
	}
	var out []*ProvisionRecord
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			return nil, fmt.Errorf("hyperv: read provision record %q: %w", e.Name(), rerr)
		}
		var rec ProvisionRecord
		if uerr := json.Unmarshal(data, &rec); uerr != nil {
			return nil, fmt.Errorf("hyperv: parse provision record %q: %w", e.Name(), uerr)
		}
		cp := rec
		out = append(out, &cp)
	}
	return out, nil
}
