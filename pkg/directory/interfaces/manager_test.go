// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingProvider is a real in-package DirectoryProvider that records the
// lifecycle calls the manager makes and serves configurable list results.
type recordingProvider struct {
	*TestDirectoryProvider

	mu            sync.Mutex
	connectCalls  int
	healthCalls   int
	connectErr    error
	userTotal     int
	groupTotal    int
	usersReturned int
	groupHasMore  bool
}

func newRecordingProvider(name string) *recordingProvider {
	return &recordingProvider{TestDirectoryProvider: NewTestDirectoryProvider(name)}
}

func (r *recordingProvider) Connect(ctx context.Context, config ProviderConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connectCalls++
	if r.connectErr != nil {
		return r.connectErr
	}
	return r.TestDirectoryProvider.Connect(ctx, config)
}

func (r *recordingProvider) IsConnected(ctx context.Context) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.TestDirectoryProvider.IsConnected(ctx)
}

func (r *recordingProvider) Disconnect(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.TestDirectoryProvider.Disconnect(ctx)
}

func (r *recordingProvider) HealthCheck(ctx context.Context) (*HealthStatus, error) {
	r.mu.Lock()
	r.healthCalls++
	r.mu.Unlock()
	return r.TestDirectoryProvider.HealthCheck(ctx)
}

func (r *recordingProvider) ListUsers(ctx context.Context, f *SearchFilters) (*UserList, error) {
	l := &UserList{TotalCount: r.userTotal}
	for i := 0; i < r.usersReturned; i++ {
		l.Users = append(l.Users, DirectoryUser{ID: "u"})
	}
	return l, nil
}

func (r *recordingProvider) ListGroups(ctx context.Context, f *SearchFilters) (*GroupList, error) {
	return &GroupList{TotalCount: r.groupTotal, HasMore: r.groupHasMore}, nil
}

func (r *recordingProvider) connects() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connectCalls
}

func newTestManager() *DirectoryProviderManager {
	return NewDirectoryProviderManager(NewDirectoryProviderFactory())
}

func TestManagerRegisterProvider_DoesNotConnect(t *testing.T) {
	m := newTestManager()
	p := newRecordingProvider("alpha")
	p.connectErr = errors.New("connect would fail")

	require.NoError(t, m.RegisterProvider("alpha", p, nil))
	assert.Equal(t, []string{"alpha"}, m.ListProviders())
	assert.Equal(t, 0, p.connects())
	assert.Equal(t, 0, p.healthCalls)
}

func TestManagerRegisterProvider_RejectsDuplicateNilAndEmpty(t *testing.T) {
	m := newTestManager()
	p := newRecordingProvider("alpha")
	require.NoError(t, m.RegisterProvider("alpha", p, nil))

	assert.Error(t, m.RegisterProvider("alpha", newRecordingProvider("again"), nil))
	assert.Error(t, m.RegisterProvider("", newRecordingProvider("x"), nil))
	assert.Error(t, m.RegisterProvider("nilp", nil, nil))
	assert.Equal(t, []string{"alpha"}, m.ListProviders())
}

func TestManagerDefaultProvider_EmptyNameResolvesToFirstRegistered(t *testing.T) {
	m := newTestManager()
	_, err := m.GetProviderOrDefault("")
	require.Error(t, err, "no providers and no default")

	a, b := newRecordingProvider("a"), newRecordingProvider("b")
	require.NoError(t, m.RegisterProvider("a", a, nil))
	require.NoError(t, m.RegisterProvider("b", b, nil))

	got, err := m.GetProviderOrDefault("")
	require.NoError(t, err)
	assert.Same(t, a, got)
	name, err := m.GetDefaultProvider()
	require.NoError(t, err)
	assert.Equal(t, "a", name)

	require.NoError(t, m.SetDefaultProvider("b"))
	got, err = m.GetProviderOrDefault("")
	require.NoError(t, err)
	assert.Same(t, b, got)

	got, err = m.GetProviderOrDefault("a")
	require.NoError(t, err)
	assert.Same(t, a, got)

	assert.Error(t, m.SetDefaultProvider("missing"))
	name, _ = m.GetDefaultProvider()
	assert.Equal(t, "b", name, "failed override leaves default unchanged")

	// Removing the default clears it rather than leaving a dangling name.
	require.NoError(t, m.RemoveProvider("b"))
	_, err = m.GetProviderOrDefault("")
	assert.Error(t, err)
}

func TestManagerConnectedProvider_ReconnectsAfterDisconnect(t *testing.T) {
	m := newTestManager()
	p := newRecordingProvider("alpha")
	require.NoError(t, m.RegisterProvider("alpha", p, nil))
	ctx := context.Background()

	got, err := m.ConnectedProvider(ctx, "alpha")
	require.NoError(t, err)
	assert.Same(t, p, got)
	assert.Equal(t, 1, p.connects())

	_, err = m.ConnectedProvider(ctx, "alpha")
	require.NoError(t, err)
	assert.Equal(t, 1, p.connects(), "already connected")

	require.NoError(t, p.Disconnect(ctx))
	_, err = m.ConnectedProvider(ctx, "alpha")
	require.NoError(t, err)
	assert.Equal(t, 2, p.connects())
}

func TestManagerConnectedProvider_ConnectsOnceUnderConcurrency(t *testing.T) {
	m := newTestManager()
	p := newRecordingProvider("alpha")
	var resolved atomic.Int32
	require.NoError(t, m.RegisterProvider("alpha", p, func(context.Context) (ProviderConfig, error) {
		resolved.Add(1)
		return ProviderConfig{}, nil
	}))

	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := m.ConnectedProvider(context.Background(), "alpha")
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, 1, p.connects())
	assert.Equal(t, int32(1), resolved.Load())
}

func TestManagerConnectedProvider_RetriesAfterConnectError(t *testing.T) {
	m := newTestManager()
	p := newRecordingProvider("alpha")
	p.connectErr = errors.New("down")
	require.NoError(t, m.RegisterProvider("alpha", p, nil))
	ctx := context.Background()

	_, err := m.ConnectedProvider(ctx, "alpha")
	require.ErrorIs(t, err, p.connectErr)
	var ce *ProviderConnectError
	require.ErrorAs(t, err, &ce)

	p.mu.Lock()
	p.connectErr = nil
	p.mu.Unlock()
	_, err = m.ConnectedProvider(ctx, "alpha")
	require.NoError(t, err)
	assert.Equal(t, 2, p.connects())
}

func TestManagerConnectedProvider_ResolverErrorIsTypedAndProviderStaysRegistered(t *testing.T) {
	m := newTestManager()
	p := newRecordingProvider("alpha")
	resolverErr := errors.New("secret missing")
	fail := true
	require.NoError(t, m.RegisterProvider("alpha", p, func(context.Context) (ProviderConfig, error) {
		if fail {
			return ProviderConfig{}, resolverErr
		}
		return ProviderConfig{}, nil
	}))
	ctx := context.Background()

	_, err := m.ConnectedProvider(ctx, "alpha")
	require.ErrorIs(t, err, resolverErr)
	var ce *ProviderConnectError
	require.ErrorAs(t, err, &ce)
	assert.Equal(t, "alpha", ce.Provider)
	assert.Equal(t, 0, p.connects())
	assert.Equal(t, []string{"alpha"}, m.ListProviders())

	fail = false
	_, err = m.ConnectedProvider(ctx, "alpha")
	require.NoError(t, err)
}

func TestManagerConnectedProvider_UnknownProvider(t *testing.T) {
	m := newTestManager()
	_, err := m.ConnectedProvider(context.Background(), "nope")
	require.Error(t, err)
}
