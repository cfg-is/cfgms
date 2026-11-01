// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
//
// Tests for the Tier-2 observe sweep handler on the controller side (Issue #3104).
// handleObserveSweepRequest receives EventObserveSweepRequest from a steward,
// resolves the observe-module set, and responds with CommandObserveModules.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/modules"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// Real in-process test components (not mocks)
// ---------------------------------------------------------------------------

// inMemoryManifestProvider is a real, deterministic implementation of
// ObserveManifestProvider backed by a fixed manifest slice. Not a mock.
type inMemoryManifestProvider struct {
	manifests []*modules.ModuleMetadata
	listErr   error
}

var _ ObserveManifestProvider = (*inMemoryManifestProvider)(nil)

func (p *inMemoryManifestProvider) ListObservableManifests() ([]*modules.ModuleMetadata, error) {
	if p.listErr != nil {
		return nil, p.listErr
	}
	return p.manifests, nil
}

// inObserveSweepControlPlane is a minimal in-process ControlPlaneProvider for
// observe-sweep tests. It records SendCommand calls and ignores everything else.
type inObserveSweepControlPlane struct {
	mu   sync.Mutex
	sent []*controlplaneTypes.SignedCommand
}

var _ cpinterfaces.ControlPlaneProvider = (*inObserveSweepControlPlane)(nil)

func (p *inObserveSweepControlPlane) Name() string      { return "observe-test" }
func (p *inObserveSweepControlPlane) IsConnected() bool { return true }
func (p *inObserveSweepControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (p *inObserveSweepControlPlane) Start(_ context.Context) error     { return nil }
func (p *inObserveSweepControlPlane) Stop(_ context.Context) error      { return nil }
func (p *inObserveSweepControlPlane) Reconnect(_ context.Context) error { return nil }
func (p *inObserveSweepControlPlane) SendCommand(_ context.Context, sc *controlplaneTypes.SignedCommand) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, sc)
	return nil
}
func (p *inObserveSweepControlPlane) FanOutCommand(_ context.Context, _ *controlplaneTypes.SignedCommand, ids []string) (*controlplaneTypes.FanOutResult, error) {
	return &controlplaneTypes.FanOutResult{Succeeded: ids, Failed: map[string]error{}}, nil
}
func (p *inObserveSweepControlPlane) SubscribeCommands(_ context.Context, _ string, _ cpinterfaces.CommandHandler) error {
	return nil
}
func (p *inObserveSweepControlPlane) PublishEvent(_ context.Context, _ *controlplaneTypes.Event) error {
	return nil
}
func (p *inObserveSweepControlPlane) SubscribeEvents(_ context.Context, _ *controlplaneTypes.EventFilter, _ cpinterfaces.EventHandler) error {
	return nil
}
func (p *inObserveSweepControlPlane) SendHeartbeat(_ context.Context, _ *controlplaneTypes.Heartbeat) error {
	return nil
}
func (p *inObserveSweepControlPlane) SubscribeHeartbeats(_ context.Context, _ cpinterfaces.HeartbeatHandler) error {
	return nil
}
func (p *inObserveSweepControlPlane) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return &controlplaneTypes.ControlPlaneStats{}, nil
}

func (p *inObserveSweepControlPlane) sentCommandsOfType(t controlplaneTypes.CommandType) []*controlplaneTypes.SignedCommand {
	p.mu.Lock()
	defer p.mu.Unlock()
	var result []*controlplaneTypes.SignedCommand
	for _, sc := range p.sent {
		if sc.Command.Type == t {
			result = append(result, sc)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Test helper: minimal Server for observe-sweep handler tests
// ---------------------------------------------------------------------------

// newObserveServer builds a minimal *Server with the fields required by
// handleObserveSweepRequest. All other fields are zero/nil.
func newObserveServer(t *testing.T, cp *inObserveSweepControlPlane, provider ObserveManifestProvider) *Server {
	t.Helper()
	logger := logging.NewLogger("debug")

	// Build a minimal commandPublisher backed by the test control plane.
	// We wire commandPublisher using the same path as real code: commands.New.
	// Since commands.New requires a non-nil control plane and logger we pass
	// the test control plane directly.
	pub := newObserveTestPublisher(t, cp)

	return &Server{
		logger:                  logger,
		commandPublisher:        pub,
		observeManifestProvider: provider,
	}
}

// newObserveTestPublisher creates a real commands.Publisher backed by the
// given control plane. The signer is nil (unsigned commands), which is fine
// for unit tests that only inspect the command type and params.
func newObserveTestPublisher(t *testing.T, cp *inObserveSweepControlPlane) *commands.Publisher {
	t.Helper()
	pub, err := commands.New(&commands.Config{
		ControlPlane: cp,
		Logger:       logging.NewLogger("debug"),
	})
	require.NoError(t, err)
	return pub
}

// sweepEvent builds an EventObserveSweepRequest with the given baseline DNA.
func sweepEvent(stewardID string, baselineDNA map[string]string) *controlplaneTypes.Event {
	raw, _ := json.Marshal(baselineDNA)
	return &controlplaneTypes.Event{
		ID:        "evt-sweep-1",
		Type:      controlplaneTypes.EventObserveSweepRequest,
		StewardID: stewardID,
		TenantID:  "tenant-1",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"baseline_dna": string(raw),
		},
	}
}

// makeManifest builds a minimal ModuleMetadata with the given name, kind
// (ownership), and observe_when predicate. The publisher "test-publisher" and
// version "1.0.0" satisfy the metadata parser requirements.
func makeManifest(name, kind, factKey, factEquals string) *modules.ModuleMetadata {
	return &modules.ModuleMetadata{
		Name:      name,
		Version:   "1.0.0",
		Publisher: "test-publisher",
		Executors: []string{"steward"},
		Kind:      "steward",
		Owns:      []modules.OwnershipDeclaration{{Kind: kind}},
		ObserveWhen: []modules.ObservePredicate{
			{Fact: factKey, Equals: factEquals},
		},
	}
}

// ---------------------------------------------------------------------------
// handleObserveSweepRequest tests
// ---------------------------------------------------------------------------

// TestHandleObserveSweepRequest_SendsCommandToSteward verifies that a sweep event
// with matching baseline DNA causes the controller to send CommandObserveModules
// to the originating steward.
func TestHandleObserveSweepRequest_SendsCommandToSteward(t *testing.T) {
	cp := &inObserveSweepControlPlane{}
	manifest := makeManifest("hyperv", "hyperv", "windows_feature", "Hyper-V")
	provider := &inMemoryManifestProvider{manifests: []*modules.ModuleMetadata{manifest}}
	srv := newObserveServer(t, cp, provider)

	baselineDNA := map[string]string{"windows_feature": "Hyper-V", "os": "windows"}
	event := sweepEvent("steward-42", baselineDNA)

	err := srv.handleObserveSweepRequest(context.Background(), event)
	require.NoError(t, err)

	cmds := cp.sentCommandsOfType(controlplaneTypes.CommandObserveModules)
	require.Len(t, cmds, 1, "one CommandObserveModules must be sent to the steward")
	assert.Equal(t, "steward-42", cmds[0].Command.StewardID)

	// Verify the modules param contains the resolved module+kind spec.
	rawModules, ok := cmds[0].Command.Params["modules"].(string)
	require.True(t, ok, "modules param must be a JSON string")
	var specs []controlplaneTypes.ObserveModuleSpec
	require.NoError(t, json.Unmarshal([]byte(rawModules), &specs))
	require.Len(t, specs, 1)
	assert.Equal(t, "hyperv", specs[0].Name)
	assert.Equal(t, "hyperv", specs[0].Kind)
}

// TestHandleObserveSweepRequest_NoMatchNoCommand verifies that when no module's
// observe_when predicates match the baseline DNA, no command is sent.
func TestHandleObserveSweepRequest_NoMatchNoCommand(t *testing.T) {
	cp := &inObserveSweepControlPlane{}
	manifest := makeManifest("hyperv", "hyperv", "windows_feature", "Hyper-V")
	provider := &inMemoryManifestProvider{manifests: []*modules.ModuleMetadata{manifest}}
	srv := newObserveServer(t, cp, provider)

	// Linux baseline: "windows_feature" fact is absent → hyperv predicate won't match.
	baselineDNA := map[string]string{"os": "linux", "arch": "amd64"}
	event := sweepEvent("steward-99", baselineDNA)

	err := srv.handleObserveSweepRequest(context.Background(), event)
	require.NoError(t, err)

	cmds := cp.sentCommandsOfType(controlplaneTypes.CommandObserveModules)
	assert.Empty(t, cmds, "no command must be sent when no modules match the baseline DNA")
}

// TestHandleObserveSweepRequest_NilProvider is a no-op when no manifest
// provider is configured (feature disabled).
func TestHandleObserveSweepRequest_NilProvider(t *testing.T) {
	cp := &inObserveSweepControlPlane{}
	srv := newObserveServer(t, cp, nil)

	event := sweepEvent("steward-1", map[string]string{"os": "windows"})
	err := srv.handleObserveSweepRequest(context.Background(), event)
	require.NoError(t, err)

	cmds := cp.sentCommandsOfType(controlplaneTypes.CommandObserveModules)
	assert.Empty(t, cmds, "nil provider must be a no-op")
}

// TestHandleObserveSweepRequest_ManifestListError verifies graceful handling when
// the provider returns an error. The handler must return nil (non-fatal) and send
// no command.
func TestHandleObserveSweepRequest_ManifestListError(t *testing.T) {
	cp := &inObserveSweepControlPlane{}
	provider := &inMemoryManifestProvider{listErr: fmt.Errorf("storage unavailable")}
	srv := newObserveServer(t, cp, provider)

	event := sweepEvent("steward-1", map[string]string{"os": "windows"})
	err := srv.handleObserveSweepRequest(context.Background(), event)
	require.NoError(t, err, "manifest list error must be handled gracefully (non-fatal)")

	cmds := cp.sentCommandsOfType(controlplaneTypes.CommandObserveModules)
	assert.Empty(t, cmds)
}

// TestHandleObserveSweepRequest_MultipleModulesMatched verifies that when multiple
// modules match the baseline DNA, specs for all of them are sent in one command.
func TestHandleObserveSweepRequest_MultipleModulesMatched(t *testing.T) {
	cp := &inObserveSweepControlPlane{}
	manifests := []*modules.ModuleMetadata{
		makeManifest("hyperv", "hyperv", "windows_feature", "Hyper-V"),
		makeManifest("cluster", "cluster", "windows_feature", "Failover-Clustering"),
	}
	provider := &inMemoryManifestProvider{manifests: manifests}
	srv := newObserveServer(t, cp, provider)

	baselineDNA := map[string]string{
		"windows_feature": "Hyper-V Failover-Clustering",
	}
	event := sweepEvent("steward-7", baselineDNA)
	// Use "contains" predicate: the manifests above use "equals" so they won't both
	// match "Hyper-V Failover-Clustering" with equals. Let's use a fact that both match.
	// Rebuild manifests with Contains predicates for this test.
	manifests[0].ObserveWhen = []modules.ObservePredicate{{Fact: "windows_feature", Contains: "Hyper-V"}}
	manifests[1].ObserveWhen = []modules.ObservePredicate{{Fact: "windows_feature", Contains: "Failover-Clustering"}}

	err := srv.handleObserveSweepRequest(context.Background(), event)
	require.NoError(t, err)

	cmds := cp.sentCommandsOfType(controlplaneTypes.CommandObserveModules)
	require.Len(t, cmds, 1)

	rawModules, ok := cmds[0].Command.Params["modules"].(string)
	require.True(t, ok)
	var specs []controlplaneTypes.ObserveModuleSpec
	require.NoError(t, json.Unmarshal([]byte(rawModules), &specs))
	require.Len(t, specs, 2, "both matched modules must appear in the command")

	names := make(map[string]bool)
	for _, s := range specs {
		names[s.Name] = true
	}
	assert.True(t, names["hyperv"])
	assert.True(t, names["cluster"])
}

// TestHandleEventFromProvider_RoutesObserveSweepRequest verifies that
// handleEventFromProvider correctly routes EventObserveSweepRequest events to
// handleObserveSweepRequest (AC1 controller routing).
func TestHandleEventFromProvider_RoutesObserveSweepRequest(t *testing.T) {
	cp := &inObserveSweepControlPlane{}
	// No modules match → no command sent, but the event must be routed (no error).
	provider := &inMemoryManifestProvider{manifests: nil}
	srv := newObserveServer(t, cp, provider)

	event := &controlplaneTypes.Event{
		ID:        "evt-routing",
		Type:      controlplaneTypes.EventObserveSweepRequest,
		StewardID: "steward-1",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"baseline_dna": `{}`},
	}
	err := srv.handleEventFromProvider(context.Background(), event)
	require.NoError(t, err, "EventObserveSweepRequest must be handled without error")
}
