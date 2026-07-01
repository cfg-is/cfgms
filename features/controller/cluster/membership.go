// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cluster

import (
	"errors"
	"sync"
	"time"
)

// MemberState is the lifecycle state of a cluster node.
type MemberState string

const (
	StateActive         MemberState = "active"
	StateDraining       MemberState = "draining"
	StateDecommissioned MemberState = "decommissioned"
)

// NodeRecord holds the identity and state of a cluster node.
type NodeRecord struct {
	ID           string
	State        MemberState
	Address      string
	RegisteredAt time.Time
}

// MembershipStore is the persistence contract for cluster node membership.
type MembershipStore interface {
	Register(node NodeRecord) error
	SetState(id string, s MemberState) error
	GetNode(id string) (NodeRecord, error)
	ListActiveNodes() []NodeRecord
}

// ErrNodeNotFound is returned when a node ID has no record in the store.
var ErrNodeNotFound = errors.New("cluster: node not found")

// InMemoryMembershipStore is a thread-safe, non-durable MembershipStore.
// Suitable for single-controller deployments and tests; not HA-safe.
type InMemoryMembershipStore struct {
	mu    sync.RWMutex
	nodes map[string]NodeRecord
}

// NewInMemoryMembershipStore returns an empty InMemoryMembershipStore.
func NewInMemoryMembershipStore() *InMemoryMembershipStore {
	return &InMemoryMembershipStore{nodes: make(map[string]NodeRecord)}
}

// Register adds or replaces a node record.
func (s *InMemoryMembershipStore) Register(node NodeRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[node.ID] = node
	return nil
}

// SetState updates the state of an existing node. Returns ErrNodeNotFound if the
// node has not been registered.
func (s *InMemoryMembershipStore) SetState(id string, state MemberState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.nodes[id]
	if !ok {
		return ErrNodeNotFound
	}
	node.State = state
	s.nodes[id] = node
	return nil
}

// GetNode returns the record for the given node ID.
func (s *InMemoryMembershipStore) GetNode(id string) (NodeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.nodes[id]
	if !ok {
		return NodeRecord{}, ErrNodeNotFound
	}
	return node, nil
}

// ListActiveNodes returns all nodes whose state is StateActive.
func (s *InMemoryMembershipStore) ListActiveNodes() []NodeRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []NodeRecord
	for _, n := range s.nodes {
		if n.State == StateActive {
			out = append(out, n)
		}
	}
	return out
}
