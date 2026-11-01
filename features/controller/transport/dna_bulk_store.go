// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	stewarddna "github.com/cfgis/cfgms/features/steward/dna"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const (
	// MaxBulkFragmentsPerSteward bounds the fragments the controller stores for one
	// steward's bulk lane. A steward is untrusted: without a bound it could grow the
	// controller's durable state without limit by inventing fragment ids.
	MaxBulkFragmentsPerSteward = 250000

	bulkManifestTenant    = "system"
	bulkManifestNamespace = "dna-bulk-manifest"
	bulkManifestCreatedBy = "dna-bulk-store"
)

// bulkShard is the persisted form of one (steward, bucket) shard.
type bulkShard struct {
	StewardID string            `json:"steward_id"`
	Bucket    int               `json:"bucket"`
	Root      string            `json:"root"` // hex AggregateRoot over Entries
	Entries   map[string]string `json:"entries"`
}

// BulkManifestStore is the durable, sharded per-steward bulk manifest: the first
// production FragmentDeltaStore. Each (steward, bucket) pair is one config store
// entry, so a delta rewrites only the buckets it touches. A bucket's root is
// persisted inside its shard, so roots survive a restart without recomputation.
type BulkManifestStore struct {
	store cfgconfig.ConfigStore

	mu     sync.Mutex
	counts map[string]int // steward -> stored fragment total, loaded lazily
}

var _ FragmentDeltaStore = (*BulkManifestStore)(nil)

// NewBulkManifestStore returns a store persisting through cs.
func NewBulkManifestStore(cs cfgconfig.ConfigStore) (*BulkManifestStore, error) {
	if cs == nil {
		return nil, errors.New("bulk manifest store: config store must not be nil")
	}
	return &BulkManifestStore{store: cs, counts: make(map[string]int)}, nil
}

// shardKey names the entry for (steward, bucket). The steward id is hashed so an
// arbitrary steward-controlled string never becomes a storage path component.
func shardKey(stewardID string, bucket int) *cfgconfig.ConfigKey {
	sum := sha256.Sum256([]byte(stewardID))
	return &cfgconfig.ConfigKey{
		TenantID:  bulkManifestTenant,
		Namespace: bulkManifestNamespace,
		Name:      hex.EncodeToString(sum[:16]) + "-" + strconv.Itoa(bucket),
	}
}

func (s *BulkManifestStore) loadShard(ctx context.Context, stewardID string, bucket int) (*bulkShard, error) {
	entry, err := s.store.GetConfig(ctx, shardKey(stewardID, bucket))
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("bulk manifest store: read bucket %d: %w", bucket, err)
	}
	var sh bulkShard
	if err := json.Unmarshal(entry.Data, &sh); err != nil {
		return nil, fmt.Errorf("bulk manifest store: decode bucket %d: %w", bucket, err)
	}
	if sh.StewardID != stewardID || sh.Bucket != bucket {
		return nil, fmt.Errorf("bulk manifest store: bucket %d entry does not belong to this steward", bucket)
	}
	if sh.Entries == nil {
		sh.Entries = map[string]string{}
	}
	return &sh, nil
}

func (sh *bulkShard) manifest() []*commonpb.ManifestEntry {
	out := make([]*commonpb.ManifestEntry, 0, len(sh.Entries))
	for id, h := range sh.Entries {
		out = append(out, &commonpb.ManifestEntry{FragmentId: id, FragmentHash: h})
	}
	return out
}

func (sh *bulkShard) entry() (*cfgconfig.ConfigEntry, error) {
	root, err := stewarddna.AggregateRoot(sh.manifest())
	if err != nil {
		return nil, err
	}
	sh.Root = root
	data, err := json.Marshal(sh)
	if err != nil {
		return nil, fmt.Errorf("bulk manifest store: encode bucket %d: %w", sh.Bucket, err)
	}
	return &cfgconfig.ConfigEntry{
		Key:       shardKey(sh.StewardID, sh.Bucket),
		Data:      data,
		Format:    cfgconfig.ConfigFormatJSON,
		CreatedBy: bulkManifestCreatedBy,
		UpdatedBy: bulkManifestCreatedBy,
	}, nil
}

// total returns the stored fragment count for a steward, loading it on first use.
// Callers hold s.mu.
func (s *BulkManifestStore) total(ctx context.Context, stewardID string) (int, error) {
	if n, ok := s.counts[stewardID]; ok {
		return n, nil
	}
	n := 0
	for b := 0; b < stewarddna.BucketCount; b++ {
		sh, err := s.loadShard(ctx, stewardID, b)
		if err != nil {
			return 0, err
		}
		if sh != nil {
			n += len(sh.Entries)
		}
	}
	s.counts[stewardID] = n
	return n, nil
}

// CurrentManifest implements FragmentDeltaStore. It returns nil when the steward
// has no stored fragments, otherwise entries sorted by fragment id.
func (s *BulkManifestStore) CurrentManifest(stewardID string) ([]*commonpb.ManifestEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := context.Background()

	var out []*commonpb.ManifestEntry
	for b := 0; b < stewarddna.BucketCount; b++ {
		sh, err := s.loadShard(ctx, stewardID, b)
		if err != nil {
			return nil, err
		}
		if sh != nil {
			out = append(out, sh.manifest()...)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetFragmentId() < out[j].GetFragmentId() })
	return out, nil
}

// BucketRoots returns the 256 persisted bucket roots for a steward. A bucket with
// no shard carries the fixed empty-bucket root.
func (s *BulkManifestStore) BucketRoots(stewardID string) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := context.Background()

	roots := make([][]byte, stewarddna.BucketCount)
	for b := range roots {
		sh, err := s.loadShard(ctx, stewardID, b)
		if err != nil {
			return nil, err
		}
		if sh == nil || len(sh.Entries) == 0 {
			roots[b] = stewarddna.EmptyBucketRoot()
			continue
		}
		r, err := hex.DecodeString(sh.Root)
		if err != nil {
			return nil, fmt.Errorf("bulk manifest store: bucket %d root: %w", b, err)
		}
		roots[b] = r
	}
	return roots, nil
}

// ApplyDelta implements FragmentDeltaStore. Every stored hash is derived from the
// fragment's canonical bytes; the steward-asserted FragmentHash is never read. A
// delta that would take the steward past MaxBulkFragmentsPerSteward is rejected
// before anything is written.
func (s *BulkManifestStore) ApplyDelta(stewardID string, fragments []*commonpb.Fragment) error {
	if len(fragments) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := context.Background()

	derived := make(map[string]string, len(fragments))
	for _, f := range fragments {
		if f == nil {
			continue
		}
		derived[f.GetFragmentId()] = stewarddna.FragmentHash(f.GetCanonicalBytes())
	}

	byBucket := make(map[int][]string)
	for id := range derived {
		b := stewarddna.BucketOf(id)
		byBucket[b] = append(byBucket[b], id)
	}

	shards := make(map[int]*bulkShard, len(byBucket))
	added := 0
	for b, ids := range byBucket {
		sh, err := s.loadShard(ctx, stewardID, b)
		if err != nil {
			return err
		}
		if sh == nil {
			sh = &bulkShard{StewardID: stewardID, Bucket: b, Entries: map[string]string{}}
		}
		for _, id := range ids {
			if _, exists := sh.Entries[id]; !exists {
				added++
			}
			sh.Entries[id] = derived[id]
		}
		shards[b] = sh
	}

	cur, err := s.total(ctx, stewardID)
	if err != nil {
		return err
	}
	if cur+added > MaxBulkFragmentsPerSteward {
		return fmt.Errorf("bulk manifest store: delta would exceed the %d fragment limit per steward", MaxBulkFragmentsPerSteward)
	}

	entries := make([]*cfgconfig.ConfigEntry, 0, len(shards))
	for _, sh := range shards {
		e, err := sh.entry()
		if err != nil {
			return err
		}
		entries = append(entries, e)
	}
	if err := s.store.StoreConfigBatch(ctx, entries); err != nil {
		delete(s.counts, stewardID)
		return fmt.Errorf("bulk manifest store: write buckets: %w", err)
	}
	s.counts[stewardID] = cur + added
	return nil
}

// RemoveFragments deletes the named fragments from the steward's manifest. Ids that
// are not stored are ignored. A bucket left empty has its entry deleted.
func (s *BulkManifestStore) RemoveFragments(stewardID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := context.Background()

	byBucket := make(map[int][]string)
	for _, id := range ids {
		b := stewarddna.BucketOf(id)
		byBucket[b] = append(byBucket[b], id)
	}

	var writes []*cfgconfig.ConfigEntry
	var deletes []*cfgconfig.ConfigKey
	removed := 0
	for b, bids := range byBucket {
		sh, err := s.loadShard(ctx, stewardID, b)
		if err != nil {
			return err
		}
		if sh == nil {
			continue
		}
		changed := false
		for _, id := range bids {
			if _, ok := sh.Entries[id]; ok {
				delete(sh.Entries, id)
				removed++
				changed = true
			}
		}
		if !changed {
			continue
		}
		if len(sh.Entries) == 0 {
			deletes = append(deletes, shardKey(stewardID, b))
			continue
		}
		e, err := sh.entry()
		if err != nil {
			return err
		}
		writes = append(writes, e)
	}

	if len(writes) > 0 {
		if err := s.store.StoreConfigBatch(ctx, writes); err != nil {
			delete(s.counts, stewardID)
			return fmt.Errorf("bulk manifest store: write buckets: %w", err)
		}
	}
	if len(deletes) > 0 {
		if err := s.store.DeleteConfigBatch(ctx, deletes); err != nil {
			delete(s.counts, stewardID)
			return fmt.Errorf("bulk manifest store: delete buckets: %w", err)
		}
	}
	if n, ok := s.counts[stewardID]; ok {
		s.counts[stewardID] = n - removed
	}
	return nil
}
