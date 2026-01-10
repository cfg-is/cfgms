// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SyncManager manages synchronization primitives across workflow executions
type SyncManager struct {
	barriers   map[string]*Barrier
	semaphores map[string]*Semaphore
	locks      map[string]*RWLock
	waitGroups map[string]*WaitGroup
	mutex      sync.RWMutex
}

// NewSyncManager creates a new synchronization manager
func NewSyncManager() *SyncManager {
	return &SyncManager{
		barriers:   make(map[string]*Barrier),
		semaphores: make(map[string]*Semaphore),
		locks:      make(map[string]*RWLock),
		waitGroups: make(map[string]*WaitGroup),
	}
}

// Barrier represents a synchronization barrier
type Barrier struct {
	count     int
	waiting   int
	completed chan struct{}
	mutex     sync.Mutex
}

// NewBarrier creates a new barrier for the specified count
func NewBarrier(count int) *Barrier {
	return &Barrier{
		count:     count,
		completed: make(chan struct{}),
	}
}

// Wait waits for all participants to reach the barrier
func (b *Barrier) Wait(ctx context.Context, timeout time.Duration) error {
	b.mutex.Lock()
	b.waiting++
	if b.waiting >= b.count {
		// Last participant arrived, release all
		close(b.completed)
		b.mutex.Unlock()
		return nil
	}
	b.mutex.Unlock()

	// Wait for completion or timeout
	if timeout > 0 {
		select {
		case <-b.completed:
			return nil
		case <-time.After(timeout):
			return fmt.Errorf("barrier timeout after %v", timeout)
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		select {
		case <-b.completed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Semaphore represents a counting semaphore
type Semaphore struct {
	permits chan struct{}
}

// NewSemaphore creates a new semaphore with the specified number of permits
func NewSemaphore(permits int) *Semaphore {
	s := &Semaphore{
		permits: make(chan struct{}, permits),
	}
	// Initialize with permits
	for i := 0; i < permits; i++ {
		s.permits <- struct{}{}
	}
	return s
}

// Acquire attempts to acquire the specified number of permits
func (s *Semaphore) Acquire(ctx context.Context, count int, timeout time.Duration) error {
	if count <= 0 {
		count = 1
	}

	// Acquire permits one by one
	acquired := 0
	defer func() {
		// If we didn't acquire all permits, release what we did acquire
		if acquired < count {
			for i := 0; i < acquired; i++ {
				select {
				case s.permits <- struct{}{}:
				default:
				}
			}
		}
	}()

	for i := 0; i < count; i++ {
		if timeout > 0 {
			select {
			case <-s.permits:
				acquired++
			case <-time.After(timeout):
				return fmt.Errorf("semaphore acquisition timeout after %v", timeout)
			case <-ctx.Done():
				return ctx.Err()
			}
		} else {
			select {
			case <-s.permits:
				acquired++
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}

// Release releases the specified number of permits
func (s *Semaphore) Release(count int) {
	if count <= 0 {
		count = 1
	}

	for i := 0; i < count; i++ {
		select {
		case s.permits <- struct{}{}:
		default:
			// Semaphore is at capacity, ignore extra releases
		}
	}
}

// RWLock represents a reader-writer lock
type RWLock struct {
	lock sync.RWMutex
}

// NewRWLock creates a new reader-writer lock
func NewRWLock() *RWLock {
	return &RWLock{}
}

// AcquireRead acquires a read lock
func (rw *RWLock) AcquireRead(ctx context.Context, timeout time.Duration) error {
	done := make(chan struct{})
	go func() {
		rw.lock.RLock()
		close(done)
	}()

	if timeout > 0 {
		select {
		case <-done:
			return nil
		case <-time.After(timeout):
			return fmt.Errorf("read lock acquisition timeout after %v", timeout)
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// AcquireWrite acquires a write lock
func (rw *RWLock) AcquireWrite(ctx context.Context, timeout time.Duration) error {
	done := make(chan struct{})
	go func() {
		rw.lock.Lock()
		close(done)
	}()

	if timeout > 0 {
		select {
		case <-done:
			return nil
		case <-time.After(timeout):
			return fmt.Errorf("write lock acquisition timeout after %v", timeout)
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// ReleaseRead releases a read lock
func (rw *RWLock) ReleaseRead() {
	rw.lock.RUnlock()
}

// ReleaseWrite releases a write lock
func (rw *RWLock) ReleaseWrite() {
	rw.lock.Unlock()
}

// WaitGroup represents a wait group for coordinating goroutines
type WaitGroup struct {
	wg sync.WaitGroup
}

// NewWaitGroup creates a new wait group
func NewWaitGroup() *WaitGroup {
	return &WaitGroup{}
}

// Add adds delta to the wait group counter
func (wg *WaitGroup) Add(delta int) {
	wg.wg.Add(delta)
}

// Done decrements the wait group counter
func (wg *WaitGroup) Done() {
	wg.wg.Done()
}

// Wait waits for the wait group counter to reach zero
func (wg *WaitGroup) Wait(ctx context.Context, timeout time.Duration) error {
	done := make(chan struct{})
	go func() {
		wg.wg.Wait()
		close(done)
	}()

	if timeout > 0 {
		select {
		case <-done:
			return nil
		case <-time.After(timeout):
			return fmt.Errorf("wait group timeout after %v", timeout)
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// SyncManager methods for managing synchronization primitives

// GetOrCreateBarrier gets or creates a barrier with the specified name and count
func (sm *SyncManager) GetOrCreateBarrier(name string, count int) (*Barrier, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if barrier, exists := sm.barriers[name]; exists {
		if barrier.count != count {
			return nil, fmt.Errorf("barrier '%s' already exists with different count: %d vs %d", name, barrier.count, count)
		}
		return barrier, nil
	}

	barrier := NewBarrier(count)
	sm.barriers[name] = barrier
	return barrier, nil
}

// GetOrCreateSemaphore gets or creates a semaphore with the specified name and permits
func (sm *SyncManager) GetOrCreateSemaphore(name string, permits int) (*Semaphore, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if semaphore, exists := sm.semaphores[name]; exists {
		return semaphore, nil
	}

	semaphore := NewSemaphore(permits)
	sm.semaphores[name] = semaphore
	return semaphore, nil
}

// GetOrCreateLock gets or creates a lock with the specified name
func (sm *SyncManager) GetOrCreateLock(name string) (*RWLock, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if lock, exists := sm.locks[name]; exists {
		return lock, nil
	}

	lock := NewRWLock()
	sm.locks[name] = lock
	return lock, nil
}

// GetOrCreateWaitGroup gets or creates a wait group with the specified name
func (sm *SyncManager) GetOrCreateWaitGroup(name string) (*WaitGroup, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if wg, exists := sm.waitGroups[name]; exists {
		return wg, nil
	}

	wg := NewWaitGroup()
	sm.waitGroups[name] = wg
	return wg, nil
}

// Cleanup removes unused synchronization primitives
func (sm *SyncManager) Cleanup() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// Remove completed barriers
	for name, barrier := range sm.barriers {
		select {
		case <-barrier.completed:
			delete(sm.barriers, name)
		default:
		}
	}

	// For now, we keep semaphores, locks, and wait groups as they might be reused
	// In a production system, you might want to implement reference counting
	// or time-based cleanup
}
