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
	state, err := s.module.Get(ctx, req.GetResourceId())
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

// Set applies the desired state from ConfigData (YAML) to the resource.
func (s *moduleServer) Set(ctx context.Context, req *proto.SetRequest) (*proto.SetResponse, error) {
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
	if configurable, ok := s.module.(modules.Configurable); ok {
		if err := configurable.Configure(cs); err != nil {
			return &proto.SetResponse{Error: fmt.Sprintf("configure: %v", err)}, nil
		}
	}

	if err := s.module.Set(ctx, req.GetResourceId(), cs); err != nil {
		return &proto.SetResponse{Error: err.Error()}, nil
	}
	return &proto.SetResponse{Applied: true}, nil
}

// Test checks compliance without applying changes. Calls Get and compares the
// result against the desired ConfigData; returns InCompliance = true when the
// current state matches all managed fields.
func (s *moduleServer) Test(ctx context.Context, req *proto.TestRequest) (*proto.TestResponse, error) {
	current, err := s.module.Get(ctx, req.GetResourceId())
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

// Shutdown triggers a graceful gRPC server stop.
func (s *moduleServer) Shutdown(_ context.Context, _ *proto.ShutdownRequest) (*proto.ShutdownResponse, error) {
	if s.srv != nil {
		go s.srv.GracefulStop()
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
