// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package registry

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockSender is a test implementation of MessageSender.
type mockSender struct {
	mu       sync.Mutex
	messages []interface{}
	err      error // if set, SendMsg returns this error
}

func (m *mockSender) SendMsg(msg interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockSender) received() []interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]interface{}, len(m.messages))
	copy(cp, m.messages)
	return cp
}

// newConn creates a test StewardConnection with sensible defaults.
func newConn(stewardID string) *StewardConnection {
	return &StewardConnection{
		StewardID:   stewardID,
		TenantPath:  "root/test",
		Sender:      &mockSender{},
		ConnectedAt: time.Now(),
		RemoteAddr:  "127.0.0.1:50051",
	}
}

// =============================================================================
// Registration tests
// =============================================================================

// TestRegistry_RegisterAndGet verifies that a registered connection can be retrieved.
func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	conn := newConn("steward-001")

	if err := reg.Register(conn); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	got, ok := reg.Get("steward-001")
	if !ok {
		t.Fatal("Get() returned false, want true")
	}
	if got != conn {
		t.Errorf("Get() = %v, want %v", got, conn)
	}
}

// TestRegistry_RegisterReplacesExisting verifies that registering the same stewardID
// replaces the previous connection and Get returns the new one.
func TestRegistry_RegisterReplacesExisting(t *testing.T) {
	reg := NewRegistry()
	conn1 := newConn("steward-001")
	conn2 := newConn("steward-001")

	if err := reg.Register(conn1); err != nil {
		t.Fatalf("Register(conn1) error = %v", err)
	}
	if err := reg.Register(conn2); err != nil {
		t.Fatalf("Register(conn2) error = %v", err)
	}

	got, ok := reg.Get("steward-001")
	if !ok {
		t.Fatal("Get() returned false after replacement, want true")
	}
	if got != conn2 {
		t.Error("Get() returned old connection, want new connection")
	}
}

// TestRegistry_GetMissing verifies that Get for an unregistered ID returns false.
func TestRegistry_GetMissing(t *testing.T) {
	reg := NewRegistry()

	_, ok := reg.Get("does-not-exist")
	if ok {
		t.Error("Get() returned true for unregistered steward, want false")
	}
}

// TestRegistry_Unregister verifies that Unregister removes the connection.
func TestRegistry_Unregister(t *testing.T) {
	reg := NewRegistry()
	conn := newConn("steward-001")

	if err := reg.Register(conn); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	reg.Unregister("steward-001")

	_, ok := reg.Get("steward-001")
	if ok {
		t.Error("Get() returned true after Unregister, want false")
	}
}

// TestRegistry_UnregisterMissing verifies that Unregister for an unregistered ID
// is a no-op and does not panic.
func TestRegistry_UnregisterMissing(t *testing.T) {
	reg := NewRegistry()

	// Should not panic.
	reg.Unregister("does-not-exist")
}

// =============================================================================
// Bulk operation tests
// =============================================================================

// TestRegistry_GetMany verifies that GetMany returns exactly the requested connected stewards.
func TestRegistry_GetMany(t *testing.T) {
	reg := NewRegistry()
	ids := []string{"s1", "s2", "s3", "s4", "s5"}
	for _, id := range ids {
		if err := reg.Register(newConn(id)); err != nil {
			t.Fatalf("Register(%s) error = %v", id, err)
		}
	}

	want := []string{"s1", "s3", "s5"}
	got := reg.GetMany(want)

	if len(got) != 3 {
		t.Fatalf("GetMany() returned %d entries, want 3", len(got))
	}
	for _, id := range want {
		if _, ok := got[id]; !ok {
			t.Errorf("GetMany() missing %s", id)
		}
	}
}

// TestRegistry_GetMany_PartialMiss verifies that GetMany only returns registered stewards
// even when some requested IDs are missing.
func TestRegistry_GetMany_PartialMiss(t *testing.T) {
	reg := NewRegistry()
	for _, id := range []string{"s1", "s2", "s3"} {
		if err := reg.Register(newConn(id)); err != nil {
			t.Fatalf("Register(%s) error = %v", id, err)
		}
	}

	got := reg.GetMany([]string{"s1", "s2", "s3", "s4", "s5"})

	if len(got) != 3 {
		t.Fatalf("GetMany() returned %d entries, want 3", len(got))
	}
	for _, id := range []string{"s1", "s2", "s3"} {
		if _, ok := got[id]; !ok {
			t.Errorf("GetMany() missing registered steward %s", id)
		}
	}
	for _, id := range []string{"s4", "s5"} {
		if _, ok := got[id]; ok {
			t.Errorf("GetMany() included unregistered steward %s", id)
		}
	}
}

// TestRegistry_GetMany_EmptyList verifies that GetMany with an empty list returns an empty map.
func TestRegistry_GetMany_EmptyList(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(newConn("s1")); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	got := reg.GetMany([]string{})
	if len(got) != 0 {
		t.Errorf("GetMany(empty) returned %d entries, want 0", len(got))
	}
}

// TestRegistry_GetAll verifies that GetAll returns all registered connections.
func TestRegistry_GetAll(t *testing.T) {
	reg := NewRegistry()
	ids := []string{"s1", "s2", "s3", "s4", "s5"}
	for _, id := range ids {
		if err := reg.Register(newConn(id)); err != nil {
			t.Fatalf("Register(%s) error = %v", id, err)
		}
	}

	got := reg.GetAll()
	if len(got) != 5 {
		t.Fatalf("GetAll() returned %d entries, want 5", len(got))
	}
	for _, id := range ids {
		if _, ok := got[id]; !ok {
			t.Errorf("GetAll() missing %s", id)
		}
	}
}

// TestRegistry_GetAll_IsCopy verifies that modifying the returned map from GetAll
// does not affect the registry's internal state.
func TestRegistry_GetAll_IsCopy(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(newConn("s1")); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	snapshot := reg.GetAll()
	// Modify the snapshot.
	snapshot["injected"] = newConn("injected")
	delete(snapshot, "s1")

	// Registry should be unaffected.
	if reg.Count() != 1 {
		t.Errorf("registry Count() = %d after snapshot modification, want 1", reg.Count())
	}
	if _, ok := reg.Get("s1"); !ok {
		t.Error("registry lost s1 after snapshot modification")
	}
	if _, ok := reg.Get("injected"); ok {
		t.Error("registry has injected entry after snapshot modification")
	}
}

// TestRegistry_Count verifies Count returns the correct number of registered connections.
func TestRegistry_Count(t *testing.T) {
	reg := NewRegistry()
	if reg.Count() != 0 {
		t.Fatalf("initial Count() = %d, want 0", reg.Count())
	}

	for i := 0; i < 3; i++ {
		if err := reg.Register(newConn(fmt.Sprintf("s%d", i))); err != nil {
			t.Fatalf("Register() error = %v", err)
		}
	}
	if reg.Count() != 3 {
		t.Errorf("Count() after 3 registrations = %d, want 3", reg.Count())
	}

	reg.Unregister("s0")
	if reg.Count() != 2 {
		t.Errorf("Count() after 1 unregistration = %d, want 2", reg.Count())
	}
}

// =============================================================================
// Callback tests
// =============================================================================

// TestRegistry_OnConnect verifies that OnConnect callback fires with the stewardID.
func TestRegistry_OnConnect(t *testing.T) {
	reg := NewRegistry()
	ch := make(chan string, 1)
	reg.OnConnect(func(stewardID string) {
		ch <- stewardID
	})

	if err := reg.Register(newConn("steward-001")); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	select {
	case got := <-ch:
		if got != "steward-001" {
			t.Errorf("OnConnect callback got %q, want %q", got, "steward-001")
		}
	case <-time.After(time.Second):
		t.Fatal("OnConnect callback was not called within timeout")
	}
}

// TestRegistry_OnDisconnect verifies that OnDisconnect callback fires after Unregister.
func TestRegistry_OnDisconnect(t *testing.T) {
	reg := NewRegistry()
	ch := make(chan string, 1)
	reg.OnDisconnect(func(stewardID string) {
		ch <- stewardID
	})

	if err := reg.Register(newConn("steward-001")); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	reg.Unregister("steward-001")

	select {
	case got := <-ch:
		if got != "steward-001" {
			t.Errorf("OnDisconnect callback got %q, want %q", got, "steward-001")
		}
	case <-time.After(time.Second):
		t.Fatal("OnDisconnect callback was not called within timeout")
	}
}

// TestRegistry_MultipleCallbacks verifies that all registered connect/disconnect
// callbacks fire when a steward connects or disconnects.
func TestRegistry_MultipleCallbacks(t *testing.T) {
	reg := NewRegistry()

	var connectCount int32
	var disconnectCount int32
	wg := sync.WaitGroup{}

	for i := 0; i < 3; i++ {
		wg.Add(2)
		reg.OnConnect(func(string) {
			atomic.AddInt32(&connectCount, 1)
			wg.Done()
		})
		reg.OnDisconnect(func(string) {
			atomic.AddInt32(&disconnectCount, 1)
			wg.Done()
		})
	}

	if err := reg.Register(newConn("s1")); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	reg.Unregister("s1")

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("callbacks not all fired: connect=%d disconnect=%d", connectCount, disconnectCount)
	}

	if atomic.LoadInt32(&connectCount) != 3 {
		t.Errorf("connect callback count = %d, want 3", connectCount)
	}
	if atomic.LoadInt32(&disconnectCount) != 3 {
		t.Errorf("disconnect callback count = %d, want 3", disconnectCount)
	}
}

// =============================================================================
// Concurrency tests
// =============================================================================

// TestRegistry_ConcurrentRegisterUnregister verifies no races occur when
// registering and unregistering from many goroutines simultaneously.
func TestRegistry_ConcurrentRegisterUnregister(t *testing.T) {
	reg := NewRegistry()
	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("s%d", i%10)
			conn := newConn(id)
			// Alternate register/unregister.
			if i%2 == 0 {
				_ = reg.Register(conn)
			} else {
				reg.Unregister(id)
			}
		}()
	}

	wg.Wait()
	// No assertions needed — the race detector catches data races.
}

// TestRegistry_ConcurrentGetMany verifies that GetMany during concurrent
// register/unregister operations does not panic and returns a consistent snapshot.
func TestRegistry_ConcurrentGetMany(t *testing.T) {
	reg := NewRegistry()
	// Pre-populate some connections.
	for i := 0; i < 10; i++ {
		_ = reg.Register(newConn(fmt.Sprintf("s%d", i)))
	}

	var wg sync.WaitGroup
	ids := []string{"s0", "s1", "s2", "s3", "s4"}

	// Writers: concurrently register and unregister.
	for i := 0; i < 20; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("s%d", i%10)
			if i%3 == 0 {
				reg.Unregister(id)
			} else {
				_ = reg.Register(newConn(id))
			}
		}()
	}

	// Readers: concurrently call GetMany.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := reg.GetMany(ids)
			// Each returned connection must actually be for the requested ID.
			for id, conn := range result {
				if conn.StewardID != id {
					t.Errorf("GetMany() returned conn.StewardID=%q for key %q", conn.StewardID, id)
				}
			}
		}()
	}

	wg.Wait()
}

// TestRegistry_ConcurrentSend verifies that multiple goroutines calling Send()
// on the same StewardConnection serialize correctly without data races.
func TestRegistry_ConcurrentSend(t *testing.T) {
	sender := &mockSender{}
	conn := &StewardConnection{
		StewardID:   "s1",
		Sender:      sender,
		ConnectedAt: time.Now(),
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			if err := conn.Send(fmt.Sprintf("msg-%d", i)); err != nil {
				t.Errorf("Send() error = %v", err)
			}
		}()
	}

	wg.Wait()

	msgs := sender.received()
	if len(msgs) != goroutines {
		t.Errorf("received %d messages, want %d", len(msgs), goroutines)
	}
}

// =============================================================================
// Connection tests
// =============================================================================

// TestStewardConnection_Send verifies that Send updates LastActivity.
func TestStewardConnection_Send(t *testing.T) {
	conn := &StewardConnection{
		StewardID: "s1",
		Sender:    &mockSender{},
	}

	before := time.Now()
	if err := conn.Send("hello"); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	after := time.Now()

	if conn.LastActivity.Before(before) || conn.LastActivity.After(after) {
		t.Errorf("LastActivity = %v, want between %v and %v", conn.LastActivity, before, after)
	}
}

// TestStewardConnection_SendError verifies that Send propagates errors from the sender.
func TestStewardConnection_SendError(t *testing.T) {
	expectedErr := errors.New("stream closed")
	conn := &StewardConnection{
		StewardID: "s1",
		Sender:    &mockSender{err: expectedErr},
	}

	err := conn.Send("msg")
	if !errors.Is(err, expectedErr) {
		t.Errorf("Send() error = %v, want %v", err, expectedErr)
	}
}

// TestStewardConnection_NilSender verifies that Register returns an error when
// the connection's Sender is nil.
func TestStewardConnection_NilSender(t *testing.T) {
	reg := NewRegistry()
	conn := &StewardConnection{
		StewardID: "s1",
		Sender:    nil, // intentionally nil
	}

	err := reg.Register(conn)
	if err == nil {
		t.Error("Register() with nil Sender should return error, got nil")
	}
}
