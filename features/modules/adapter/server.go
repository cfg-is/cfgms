// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package adapter bridges the in-process modules.Module interface to the
// ModuleService gRPC contract. Each stdlib module cmd/main.go creates a
// ModuleServiceServer via New and registers it with a grpc.Server.
package adapter

import (
	"context"
	"fmt"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/modules"
	"gopkg.in/yaml.v3"
)

// moduleServer adapts a modules.Module to the proto.ModuleServiceServer interface.
type moduleServer struct {
	proto.UnimplementedModuleServiceServer
	module     modules.Module
	moduleName string
	srv        interface{ GracefulStop() }
}

// New wraps module in a ModuleServiceServer that translates gRPC calls to
// modules.Module calls. moduleName is reported in the Handshake capabilities list.
// The grpcServer parameter is used by Shutdown to call GracefulStop.
func New(m modules.Module, moduleName string, grpcServer interface{ GracefulStop() }) proto.ModuleServiceServer {
	return &moduleServer{
		module:     m,
		moduleName: moduleName,
		srv:        grpcServer,
	}
}

// Handshake reports the module name as its capability.
func (s *moduleServer) Handshake(_ context.Context, _ *proto.HandshakeRequest) (*proto.HandshakeResponse, error) {
	return &proto.HandshakeResponse{
		Capabilities: []string{s.moduleName},
	}, nil
}

// Get retrieves the current resource state and returns it as YAML-encoded ConfigData.
func (s *moduleServer) Get(ctx context.Context, req *proto.GetRequest) (*proto.GetResponse, error) {
	return moduleGet(ctx, s.module, req)
}

// Set applies the desired state from ConfigData (YAML) to the resource.
func (s *moduleServer) Set(ctx context.Context, req *proto.SetRequest) (*proto.SetResponse, error) {
	return moduleSet(ctx, s.module, req)
}

// Test checks compliance without applying changes. Calls Get and compares the
// result against the desired ConfigData; returns InCompliance = true when the
// current state matches all managed fields.
func (s *moduleServer) Test(ctx context.Context, req *proto.TestRequest) (*proto.TestResponse, error) {
	return moduleTest(ctx, s.module, req)
}

// Shutdown triggers a graceful gRPC server stop.
func (s *moduleServer) Shutdown(_ context.Context, _ *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	return moduleShutdown(s.srv)
}

// NewWorkflow wraps module in a WorkflowModuleServiceServer that translates
// gRPC calls to modules.Module calls — the workflow-kind (controller-executed)
// counterpart to New. Out-of-process workflow module binaries (manifests
// declaring executors: [controller], ADR-006) register the returned server
// instead of New's ModuleServiceServer, since they are resolved via
// WorkflowModuleFactory / features/workflow/runtime rather than the steward
// module runtime and so speak WorkflowModuleService, not ModuleService — the
// two contracts share every message type except Handshake (module.proto /
// workflow_module.proto), which is why every RPC below except Handshake
// delegates to the same helpers as moduleServer.
// moduleName is reported in the Handshake capabilities list. The grpcServer
// parameter is used by Shutdown to call GracefulStop.
func NewWorkflow(m modules.Module, moduleName string, grpcServer interface{ GracefulStop() }) proto.WorkflowModuleServiceServer {
	return &workflowModuleServer{
		module:     m,
		moduleName: moduleName,
		srv:        grpcServer,
	}
}

// workflowModuleServer adapts a modules.Module to the proto.WorkflowModuleServiceServer interface.
type workflowModuleServer struct {
	proto.UnimplementedWorkflowModuleServiceServer
	module     modules.Module
	moduleName string
	srv        interface{ GracefulStop() }
}

// Handshake reports the module name as its capability.
//
// req.TenantId / req.AuthToken are not yet consumed here: the workflow engine
// does not populate them today (features/workflow/runtime.Start's Handshake
// call leaves both fields at their zero value), so per-call tenant scoping
// for Get/Set continues to rely on ctx (ctxkeys.TenantID) exactly as
// documented on entra_user.requireExecutionTenant. Wiring WorkflowHandshakeRequest's
// tenant_id/auth_token through the engine -> module_loader -> runtime.Start
// call chain is a separate, cross-cutting runtime change, not specific to
// any one module (Issue #4325).
func (s *workflowModuleServer) Handshake(_ context.Context, _ *proto.WorkflowHandshakeRequest) (*proto.WorkflowHandshakeResponse, error) {
	return &proto.WorkflowHandshakeResponse{
		Capabilities: []string{s.moduleName},
	}, nil
}

// Get retrieves the current resource state and returns it as YAML-encoded ConfigData.
func (s *workflowModuleServer) Get(ctx context.Context, req *proto.GetRequest) (*proto.GetResponse, error) {
	return moduleGet(ctx, s.module, req)
}

// Set applies the desired state from ConfigData (YAML) to the resource.
func (s *workflowModuleServer) Set(ctx context.Context, req *proto.SetRequest) (*proto.SetResponse, error) {
	return moduleSet(ctx, s.module, req)
}

// Test checks compliance without applying changes.
func (s *workflowModuleServer) Test(ctx context.Context, req *proto.TestRequest) (*proto.TestResponse, error) {
	return moduleTest(ctx, s.module, req)
}

// Shutdown triggers a graceful gRPC server stop.
func (s *workflowModuleServer) Shutdown(_ context.Context, _ *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	return moduleShutdown(s.srv)
}

// moduleGet is the shared Get implementation for both the ModuleService and
// WorkflowModuleService adapters (their GetRequest/GetResponse types are the
// same proto messages, defined once in module.proto).
func moduleGet(ctx context.Context, m modules.Module, req *proto.GetRequest) (*proto.GetResponse, error) {
	state, err := m.Get(ctx, req.GetResourceId())
	if err != nil {
		return nil, err
	}
	if state == nil {
		return &proto.GetResponse{}, nil
	}

	data, err := yaml.Marshal(state.AsMap())
	if err != nil {
		return nil, fmt.Errorf("marshal config state: %w", err)
	}
	return &proto.GetResponse{ConfigData: string(data)}, nil
}

// moduleSet is the shared Set implementation for both adapters.
func moduleSet(ctx context.Context, m modules.Module, req *proto.SetRequest) (*proto.SetResponse, error) {
	// Deserialise the YAML config map and wrap it as a mapConfigState.
	var configMap map[string]interface{}
	if err := yaml.Unmarshal([]byte(req.GetConfigData()), &configMap); err != nil {
		return &proto.SetResponse{Error: fmt.Sprintf("invalid config YAML: %v", err)}, nil
	}

	if configMap == nil {
		configMap = make(map[string]interface{})
	}

	cs := &mapConfigState{m: configMap}

	// If the module supports Configure, call it to prime AllowedBasePath before Set.
	if configurable, ok := m.(modules.Configurable); ok {
		if err := configurable.Configure(cs); err != nil {
			return &proto.SetResponse{Error: fmt.Sprintf("configure: %v", err)}, nil
		}
	}

	if err := m.Set(ctx, req.GetResourceId(), cs); err != nil {
		return &proto.SetResponse{Error: err.Error()}, nil
	}
	return &proto.SetResponse{Applied: true}, nil
}

// moduleTest is the shared Test implementation for both adapters. Calls Get
// and compares the result against the desired ConfigData; returns
// InCompliance = true when the current state matches all managed fields.
func moduleTest(ctx context.Context, m modules.Module, req *proto.TestRequest) (*proto.TestResponse, error) {
	current, err := m.Get(ctx, req.GetResourceId())
	if err != nil {
		return nil, err
	}

	var desiredMap map[string]interface{}
	if err := yaml.Unmarshal([]byte(req.GetConfigData()), &desiredMap); err != nil {
		return nil, fmt.Errorf("invalid desired config YAML: %w", err)
	}

	if current == nil {
		return &proto.TestResponse{InCompliance: false, Diff: "resource absent"}, nil
	}

	currentMap := current.AsMap()

	// Check each field in the desired config against the current state.
	var diffs []string
	for k, desired := range desiredMap {
		if currentVal, ok := currentMap[k]; ok {
			if fmt.Sprintf("%v", currentVal) != fmt.Sprintf("%v", desired) {
				diffs = append(diffs, fmt.Sprintf("%s: current=%v desired=%v", k, currentVal, desired))
			}
		} else {
			diffs = append(diffs, fmt.Sprintf("%s: missing in current state (desired=%v)", k, desired))
		}
	}

	if len(diffs) > 0 {
		return &proto.TestResponse{InCompliance: false, Diff: fmt.Sprintf("%v", diffs)}, nil
	}
	return &proto.TestResponse{InCompliance: true}, nil
}

// moduleShutdown is the shared Shutdown implementation for both adapters.
func moduleShutdown(srv interface{ GracefulStop() }) (*proto.ShutdownResponse, error) {
	if srv != nil {
		go srv.GracefulStop()
	}
	return &proto.ShutdownResponse{}, nil
}

// mapConfigState adapts a YAML-decoded map to modules.ConfigState.
type mapConfigState struct {
	m map[string]interface{}
}

func (c *mapConfigState) AsMap() map[string]interface{} { return c.m }
func (c *mapConfigState) ToYAML() ([]byte, error)       { return yaml.Marshal(c.m) }
func (c *mapConfigState) FromYAML(data []byte) error    { return yaml.Unmarshal(data, &c.m) }
func (c *mapConfigState) Validate() error               { return nil }
func (c *mapConfigState) GetManagedFields() []string    { return nil }
