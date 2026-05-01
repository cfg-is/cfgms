// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transport

import (
	"errors"
	"sync"
)

// MaxConcurrentPerTenant is the maximum number of in-flight requests allowed
// for a single tenant. Requests beyond this limit receive ErrTenantQueueFull.
const MaxConcurrentPerTenant = 32

// ErrTenantQueueFull is returned by Acquire when the tenant's slot is full.
var ErrTenantQueueFull = errors.New("tenant request queue full")

// TenantQueue enforces a per-tenant concurrency limit using buffered channels
// as semaphores. Entries are created lazily on first Acquire and are never
// deleted (bounded by number of active tenants).
type TenantQueue struct {
	m sync.Map // map[string]chan struct{}
}

// NewTenantQueue creates a new TenantQueue.
func NewTenantQueue() *TenantQueue {
	return &TenantQueue{}
}

// Acquire attempts to take a slot for tenantID. Returns ErrTenantQueueFull
// immediately (non-blocking) if the tenant's concurrency limit is reached.
func (q *TenantQueue) Acquire(tenantID string) error {
	ch := q.semaphoreFor(tenantID)
	select {
	case ch <- struct{}{}:
		return nil
	default:
		return ErrTenantQueueFull
	}
}

// Release returns a slot for tenantID.
func (q *TenantQueue) Release(tenantID string) {
	ch := q.semaphoreFor(tenantID)
	<-ch
}

func (q *TenantQueue) semaphoreFor(tenantID string) chan struct{} {
	v, _ := q.m.LoadOrStore(tenantID, make(chan struct{}, MaxConcurrentPerTenant))
	return v.(chan struct{})
}
