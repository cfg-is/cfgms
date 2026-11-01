// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ErrDomainOwnedByOtherTenant is returned when a directory domain is already
// registered to a different tenant. It deliberately carries no tenant id.
var ErrDomainOwnedByOtherTenant = errors.New("directory domain is already claimed by another tenant")

var errRegistryNoChange = errors.New("directory domain registry: no change")

// domainRecord is the registry entry for one directory domain: the owning tenant and
// the stewards whose device cfg currently declares the domain. The domain is
// released when the last declarer drops it.
type domainRecord struct {
	TenantID  string   `json:"tenant_id"`
	Declarers []string `json:"declarers"`
}

// DirectoryDomainRegistry guarantees one owning tenant per directory domain without
// scanning tenants. An entry lives at ConfigKey{TenantID: "_global", Namespace:
// "directory-domains", Name: <normalized domain>} (config stores reject an empty tenant). The first tenant to save a device
// cfg declaring a domain creates it (CreateIfAbsent); a second tenant's save is
// rejected until the first releases it.
//
// Atomicity is the shared config-store helper's (CreateIfAbsent / AtomicUpdate), so
// it is cluster-atomic exactly when the store is (config.ClusterAtomic).
type DirectoryDomainRegistry struct {
	store cfgconfig.ConfigStore
}

// NewDirectoryDomainRegistry returns a registry over store.
func NewDirectoryDomainRegistry(store cfgconfig.ConfigStore) *DirectoryDomainRegistry {
	return &DirectoryDomainRegistry{store: store}
}

func domainKey(domain string) *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: egtypes.DirectoryDomainsTenantID, Namespace: egtypes.DirectoryDomainsNamespace, Name: domain}
}

func encodeRecord(domain string, rec domainRecord) (*cfgconfig.ConfigEntry, error) {
	sort.Strings(rec.Declarers)
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("encode domain registry entry: %w", err)
	}
	now := time.Now()
	return &cfgconfig.ConfigEntry{
		Key: domainKey(domain), Data: data, Format: cfgconfig.ConfigFormatJSON,
		CreatedAt: now, UpdatedAt: now, CreatedBy: "directory-domain-registry", UpdatedBy: "directory-domain-registry",
		Source: "cfgms-controller", Tags: []string{"directory-domain"},
	}, nil
}

func decodeRecord(e *cfgconfig.ConfigEntry) (domainRecord, error) {
	var rec domainRecord
	if e == nil {
		return rec, nil
	}
	if err := json.Unmarshal(e.Data, &rec); err != nil {
		return rec, fmt.Errorf("decode domain registry entry: %w", err)
	}
	return rec, nil
}

// Owner returns the tenant that owns domain. found is false when no tenant does,
// including an entry whose last declarer has gone.
func (r *DirectoryDomainRegistry) Owner(ctx context.Context, domain string) (tenantID string, found bool, err error) {
	e, err := r.store.GetConfig(ctx, domainKey(domain))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read domain registry: %w", err)
	}
	rec, err := decodeRecord(e)
	if err != nil {
		return "", false, err
	}
	if rec.TenantID == "" || len(rec.Declarers) == 0 {
		return "", false, nil
	}
	return rec.TenantID, true, nil
}

// Check reports ErrDomainOwnedByOtherTenant when domain belongs to a tenant other
// than tenantID. It never writes, so dry-run validation can use it.
func (r *DirectoryDomainRegistry) Check(ctx context.Context, domain, tenantID string) error {
	owner, found, err := r.Owner(ctx, domain)
	if err != nil {
		return err
	}
	if found && owner != tenantID {
		return ErrDomainOwnedByOtherTenant
	}
	return nil
}

// Claim registers stewardID's device cfg as a declarer of domain for tenantID.
// added reports whether this call added the declarer (false when it was already
// registered), so a caller can undo exactly what it did. A domain owned by another
// tenant fails with ErrDomainOwnedByOtherTenant.
func (r *DirectoryDomainRegistry) Claim(ctx context.Context, domain, tenantID, stewardID string) (added bool, err error) {
	entry, err := encodeRecord(domain, domainRecord{TenantID: tenantID, Declarers: []string{stewardID}})
	if err != nil {
		return false, err
	}
	switch err := cfgconfig.CreateIfAbsent(ctx, r.store, entry); {
	case err == nil:
		return true, nil
	case !errors.Is(err, cfgconfig.ErrAlreadyExists):
		return false, err
	}
	err = cfgconfig.AtomicUpdate(ctx, r.store, domainKey(domain), func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		rec, err := decodeRecord(cur)
		if err != nil {
			return nil, err
		}
		if len(rec.Declarers) > 0 && rec.TenantID != tenantID {
			return nil, ErrDomainOwnedByOtherTenant
		}
		added = false
		if rec.TenantID != tenantID {
			rec = domainRecord{TenantID: tenantID}
		}
		if !containsStr(rec.Declarers, stewardID) {
			rec.Declarers = append(rec.Declarers, stewardID)
			added = true
		}
		if !added {
			return nil, errRegistryNoChange
		}
		return encodeRecord(domain, rec)
	})
	if errors.Is(err, errRegistryNoChange) {
		return false, nil
	}
	return added && err == nil, err
}

// Release removes stewardID as a declarer of domain for tenantID. released reports
// that the domain now has no declarer, so the caller must retract the tenant's
// directory entities for it and then Remove the entry. A release by a tenant that
// does not own the domain is a no-op.
func (r *DirectoryDomainRegistry) Release(ctx context.Context, domain, tenantID, stewardID string) (released bool, err error) {
	emptied := false
	err = cfgconfig.AtomicUpdate(ctx, r.store, domainKey(domain), func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		emptied = false
		if cur == nil {
			return nil, errRegistryNoChange
		}
		rec, err := decodeRecord(cur)
		if err != nil {
			return nil, err
		}
		if rec.TenantID != tenantID || !containsStr(rec.Declarers, stewardID) {
			return nil, errRegistryNoChange
		}
		kept := rec.Declarers[:0:0]
		for _, d := range rec.Declarers {
			if d != stewardID {
				kept = append(kept, d)
			}
		}
		rec.Declarers = kept
		emptied = len(kept) == 0
		return encodeRecord(domain, rec)
	})
	if errors.Is(err, errRegistryNoChange) {
		return false, nil
	}
	return emptied && err == nil, err
}

// StaleOwner reports the tenant that last owned domain when its entry has no
// declarer left, i.e. a release whose cleanup (entity retraction, entry removal)
// may not have completed. ok is false for an absent or still-owned entry.
func (r *DirectoryDomainRegistry) StaleOwner(ctx context.Context, domain string) (tenantID string, ok bool, err error) {
	e, err := r.store.GetConfig(ctx, domainKey(domain))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read domain registry: %w", err)
	}
	rec, err := decodeRecord(e)
	if err != nil {
		return "", false, err
	}
	if len(rec.Declarers) > 0 || rec.TenantID == "" {
		return "", false, nil
	}
	return rec.TenantID, true, nil
}

// Remove deletes the entry for domain if it still has no declarer. An emptied entry
// already reads as unowned (Owner, Check and Claim treat it as absent), so a lost
// race with a concurrent Claim only leaves the entry for that Claim to refill; the
// re-read keeps a refilled entry.
func (r *DirectoryDomainRegistry) Remove(ctx context.Context, domain string) error {
	if _, ok, err := r.StaleOwner(ctx, domain); err != nil || !ok {
		return err
	}
	if err := r.store.DeleteConfig(ctx, domainKey(domain)); err != nil && !errors.Is(err, cfgconfig.ErrConfigNotFound) {
		return fmt.Errorf("remove domain registry entry: %w", err)
	}
	return nil
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
