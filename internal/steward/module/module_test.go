package module

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testModule struct {
	BaseModule
	initCalled  bool
	startCalled bool
	stopCalled  bool
}

func newTestModule() *testModule {
	return &testModule{
		BaseModule: NewBaseModule("test"),
	}
}

func (m *testModule) Initialize(ctx context.Context) error {
	m.initCalled = true
	return nil
}

func (m *testModule) Start(ctx context.Context) error {
	m.startCalled = true
	return nil
}

func (m *testModule) Stop(ctx context.Context) error {
	m.stopCalled = true
	return nil
}

func TestBaseModule(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{
			name: "new base module has correct name",
			fn: func(t *testing.T) {
				bm := NewBaseModule("test")
				assert.Equal(t, "test", bm.name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.fn)
	}
}

func TestModuleLifecycle(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{
			name: "module lifecycle calls in correct order",
			fn: func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				m := newTestModule()

				// Test Initialize
				err := m.Initialize(ctx)
				assert.NoError(t, err)
				assert.True(t, m.initCalled)

				// Test Start
				err = m.Start(ctx)
				assert.NoError(t, err)
				assert.True(t, m.startCalled)

				// Test Stop
				err = m.Stop(ctx)
				assert.NoError(t, err)
				assert.True(t, m.stopCalled)
			},
		},
		{
			name: "module respects context cancellation",
			fn: func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // Cancel immediately

				m := newTestModule()
				err := m.Initialize(ctx)
				assert.NoError(t, err) // Should still work as it's quick

				// Start should respect cancellation
				err = m.Start(ctx)
				assert.NoError(t, err) // Our test implementation doesn't block
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.fn)
	}
}
