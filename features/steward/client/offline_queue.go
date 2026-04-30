// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client provides offline report queueing for steward-to-controller reports.
//
// Issue #419: when the controller is unreachable, reports are queued locally
// and delivered in order once connectivity is restored.
// Issue #920: queue file is encrypted at rest with AES-256-GCM.
package client

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// offlineQueueKeySlot is the secrets slot used to persist the AES-256 encryption key.
const offlineQueueKeySlot = "steward/offline-queue-key"

// OfflineQueueConfig configures the offline report queue.
type OfflineQueueConfig struct {
	// Dir is the directory used for durable persistence of queued events.
	// If empty the queue is in-memory only — events are lost on restart but
	// the queue is otherwise fully functional.
	Dir string

	// MaxSize is the maximum number of events to retain in the queue.
	// When the queue is full the oldest event is evicted to make room.
	// Defaults to 1000.
	MaxSize int

	// MaxAge is the maximum time an event is retained before being discarded.
	// Defaults to 24 hours.
	MaxAge time.Duration

	// SecretStore is used to persist the AES-256-GCM encryption key.
	// If nil, a per-session random key is generated (not persisted across restarts).
	SecretStore secretsif.SecretStore

	// Logger receives diagnostic messages. May be nil.
	Logger logging.Logger
}

// QueuedEvent wraps an event with persistence metadata.
type QueuedEvent struct {
	Event     *cpTypes.Event `json:"event"`
	QueuedAt  time.Time      `json:"queued_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	// Sequence is a monotonically increasing counter used to verify ordering
	// after a load-from-disk round-trip.
	Sequence int64 `json:"sequence"`
}

// OfflineQueue persists steward-to-controller events locally while the
// controller is unreachable and delivers them in order on reconnect.
//
// Thread-safe: all public methods can be called from multiple goroutines.
type OfflineQueue struct {
	mu            sync.Mutex
	entries       []*QueuedEvent
	seenIDs       map[string]struct{}
	config        OfflineQueueConfig
	seq           int64
	encryptionKey []byte // 32-byte AES-256 key; nil only when Dir is empty
}

// queueState is the on-disk format.
type queueState struct {
	Entries []*QueuedEvent `json:"entries"`
	NextSeq int64          `json:"next_seq"`
}

// NewOfflineQueue creates a new offline queue, applying defaults and loading
// any events persisted on disk from a previous run.
func NewOfflineQueue(cfg OfflineQueueConfig) (*OfflineQueue, error) {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 1000
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 24 * time.Hour
	}

	q := &OfflineQueue{
		seenIDs: make(map[string]struct{}),
		config:  cfg,
	}

	if cfg.Dir != "" {
		key, err := q.loadOrGenerateKey(cfg.SecretStore)
		if err != nil {
			return nil, fmt.Errorf("failed to initialise offline-queue encryption key: %w", err)
		}
		q.encryptionKey = key

		if err := q.load(); err != nil {
			if cfg.Logger != nil {
				cfg.Logger.Warn("Failed to load offline queue from disk, starting empty",
					"dir", cfg.Dir, "error", err)
			}
		}
	}

	return q, nil
}

// loadOrGenerateKey retrieves the AES-256 encryption key from the SecretStore,
// generating and persisting 32 random bytes if the slot is absent.
func (q *OfflineQueue) loadOrGenerateKey(store secretsif.SecretStore) ([]byte, error) {
	ctx := context.Background()

	if store != nil {
		secret, err := store.GetSecret(ctx, offlineQueueKeySlot)
		if err == nil && secret != nil && len(secret.Value) > 0 {
			key, decErr := hex.DecodeString(secret.Value)
			if decErr == nil && len(key) == 32 {
				return key, nil
			}
		}
	}

	// Generate a fresh 32-byte key.
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	if store != nil {
		if storeErr := store.StoreSecret(ctx, &secretsif.SecretRequest{
			Key:         offlineQueueKeySlot,
			Value:       hex.EncodeToString(key),
			Description: "AES-256-GCM key for offline event queue encryption",
			CreatedBy:   "steward",
		}); storeErr != nil {
			// Key persists in memory only this session; queue contents are lost on restart.
			if q.config.Logger != nil {
				q.config.Logger.Warn("Failed to persist offline queue encryption key — queue will not survive restart",
					map[string]interface{}{"error": storeErr.Error()})
			}
		}
	}

	return key, nil
}

// Enqueue adds an event to the queue. Returns true if the event was accepted,
// false if it was rejected (duplicate ID).
//
// When the queue is at MaxSize the oldest entry is evicted to make room. This
// ensures the queue never grows unbounded while still making forward progress.
func (q *OfflineQueue) Enqueue(event *cpTypes.Event) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Deduplication: reject events whose IDs are already present.
	if _, seen := q.seenIDs[event.ID]; seen {
		return false
	}

	// Evict expired entries before checking capacity.
	q.evictExpiredLocked()

	// If at capacity, drop the oldest event to make room.
	if len(q.entries) >= q.config.MaxSize {
		if len(q.entries) > 0 {
			oldest := q.entries[0]
			delete(q.seenIDs, oldest.Event.ID)
			q.entries = q.entries[1:]
		}
	}

	q.seq++
	entry := &QueuedEvent{
		Event:     event,
		QueuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(q.config.MaxAge),
		Sequence:  q.seq,
	}
	q.entries = append(q.entries, entry)
	q.seenIDs[event.ID] = struct{}{}

	if err := q.saveLocked(); err != nil && q.config.Logger != nil {
		q.config.Logger.Warn("Failed to persist offline queue to disk after enqueue",
			"error", err, "queue_depth", len(q.entries))
	}
	return true
}

// Drain calls publishFn for each queued event in insertion order. It stops at
// the first error to preserve delivery ordering — the failed event and all
// subsequent events remain in the queue for the next attempt.
//
// Returns the number of events successfully delivered.
func (q *OfflineQueue) Drain(publishFn func(*cpTypes.Event) error) int {
	delivered := 0

	for {
		// Peek at the head of queue under the lock.
		q.mu.Lock()
		q.evictExpiredLocked()
		if len(q.entries) == 0 {
			q.mu.Unlock()
			break
		}
		entry := q.entries[0]
		q.mu.Unlock()

		// Call publishFn outside the lock — it may block.
		if err := publishFn(entry.Event); err != nil {
			// Stop on first failure to maintain strict ordering.
			break
		}

		// Remove the successfully delivered entry.
		q.mu.Lock()
		// Re-verify the head is still the same entry (concurrent drain safety).
		if len(q.entries) > 0 && q.entries[0].Sequence == entry.Sequence {
			delete(q.seenIDs, q.entries[0].Event.ID)
			q.entries = q.entries[1:]
			if err := q.saveLocked(); err != nil && q.config.Logger != nil {
				q.config.Logger.Warn("Failed to persist offline queue to disk after drain",
					"error", err, "queue_depth", len(q.entries))
			}
		}
		q.mu.Unlock()

		delivered++
	}

	return delivered
}

// Len returns the number of events currently in the queue.
func (q *OfflineQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.entries)
}

// evictExpiredLocked removes entries whose ExpiresAt is in the past.
// Must be called with q.mu held.
func (q *OfflineQueue) evictExpiredLocked() {
	now := time.Now()
	valid := q.entries[:0]
	for _, e := range q.entries {
		if e.ExpiresAt.After(now) {
			valid = append(valid, e)
		} else {
			delete(q.seenIDs, e.Event.ID)
		}
	}
	q.entries = valid
}

// queueFilePath returns the path of the encrypted persistence file.
func (q *OfflineQueue) queueFilePath() string {
	return filepath.Join(q.config.Dir, "offline_queue.enc")
}

// saveLocked writes the current queue state to disk atomically, encrypted with
// AES-256-GCM. Format: [12-byte nonce][ciphertext + 16-byte GCM auth tag].
// Must be called with q.mu held.
// A no-op when Dir is empty (in-memory mode).
func (q *OfflineQueue) saveLocked() error {
	if q.config.Dir == "" {
		return nil
	}

	if err := os.MkdirAll(q.config.Dir, 0700); err != nil {
		return err
	}

	data, err := json.Marshal(&queueState{Entries: q.entries, NextSeq: q.seq})
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(q.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, data, nil)
	payload := append(nonce, ciphertext...) // nonce prepended for decrypt

	// Atomic write: write to .tmp then rename so readers never see partial state.
	tmpPath := q.queueFilePath() + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, q.queueFilePath())
}

// load reads and decrypts persisted queue state from disk, filtering out expired
// entries. Called once from NewOfflineQueue before the queue is used by any
// goroutine, so no locking is required.
//
// Legacy plaintext offline_queue.json files are deleted on startup with an
// Info log — they cannot be decrypted and are treated as stale.
func (q *OfflineQueue) load() error {
	q.deleteLegacyPlaintextFile()

	data, err := os.ReadFile(q.queueFilePath())
	if os.IsNotExist(err) {
		return nil // No file yet — start with an empty queue.
	}
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(q.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher for decryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM for decryption: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return fmt.Errorf("encrypted queue file is too short (len=%d)", len(data))
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Authentication failure — file is corrupted or tampered with.
		return fmt.Errorf("failed to decrypt queue file (authentication failure): %w", err)
	}

	var state queueState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return fmt.Errorf("failed to unmarshal queue state: %w", err)
	}

	now := time.Now()
	q.seq = state.NextSeq

	for _, entry := range state.Entries {
		if entry == nil || entry.Event == nil {
			continue
		}
		if !entry.ExpiresAt.After(now) {
			continue // Expired during downtime — discard.
		}
		q.entries = append(q.entries, entry)
		q.seenIDs[entry.Event.ID] = struct{}{}
	}

	return nil
}

// deleteLegacyPlaintextFile removes the pre-920 plaintext offline_queue.json if
// present. It cannot be decrypted so we discard it and start fresh.
func (q *OfflineQueue) deleteLegacyPlaintextFile() {
	legacyPath := filepath.Join(q.config.Dir, "offline_queue.json")
	if _, err := os.Stat(legacyPath); os.IsNotExist(err) {
		return
	}
	if err := os.Remove(legacyPath); err == nil {
		if q.config.Logger != nil {
			q.config.Logger.Info("Deleted legacy plaintext offline queue file; starting fresh with encrypted queue",
				"path", legacyPath)
		}
	}
}
