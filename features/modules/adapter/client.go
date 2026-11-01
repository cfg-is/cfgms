// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package adapter

import (
	"context"
	"fmt"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/contract"
	"gopkg.in/yaml.v3"
)

// Client adapts the gRPC client half of a started out-of-process module
// (ModuleHandle.Client from features/steward/modules/runtime) into an
// in-process modules.Module, so the steward convergence loop can call Get/Set
// on a bundle module exactly as it would a built-in. The mirror image of
// moduleServer in server.go: that type wraps a modules.Module to serve the
// ModuleService contract; this type wraps a ModuleService client back into a
// modules.Module.
type Client struct {
	client     contract.StewardModuleClient
	moduleName string
}

// NewClient wraps client in a modules.Module. moduleName identifies the
// module in returned errors; callers typically pass the bundle's manifest name.
func NewClient(client contract.StewardModuleClient, moduleName string) *Client {
	return &Client{client: client, moduleName: moduleName}
}

var _ modules.Module = (*Client)(nil)

// Get retrieves the current resource state over gRPC.
//
// A transport-level failure — including a module process that has already
// exited, which surfaces through the gRPC client as a connection error — is
// returned as-is, wrapped with module/resource context; it is never mistaken
// for a successful empty result.
//
// The module side returns an empty ConfigData when its own Get returns a nil
// ConfigState (see moduleGet in server.go); this maps to a nil ConfigState
// here too, rather than to a non-nil ConfigState wrapping an empty map, so a
// caller cannot mistake "no state" for a populated zero value.
func (c *Client) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	resp, err := c.client.Get(ctx, &proto.GetRequest{ResourceId: resourceID})
	if err != nil {
		return nil, fmt.Errorf("module %s: get %s: %w", c.moduleName, resourceID, err)
	}

	data := resp.GetConfigData()
	if data == "" {
		return nil, nil
	}

	var configMap map[string]interface{}
	if err := yaml.Unmarshal([]byte(data), &configMap); err != nil {
		return nil, fmt.Errorf("module %s: get %s: invalid config data from module: %w", c.moduleName, resourceID, err)
	}

	return &mapConfigState{m: configMap}, nil
}

// Set applies the desired state over gRPC.
//
// A transport-level failure is returned as-is. A module-side failure is also
// returned as an error even though it carries no gRPC error: moduleSet
// (server.go) puts a module Set failure, and an invalid-config-YAML failure,
// inside the response body (SetResponse.Error) rather than as a gRPC error —
// a client that only checked the gRPC error would record every failed apply
// as a success. Applied == false with no Error message is treated as a
// failure too, rather than silently treated as success.
func (c *Client) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	data, err := config.ToYAML()
	if err != nil {
		return fmt.Errorf("module %s: set %s: marshal config: %w", c.moduleName, resourceID, err)
	}

	resp, err := c.client.Set(ctx, &proto.SetRequest{ResourceId: resourceID, ConfigData: string(data)})
	if err != nil {
		return fmt.Errorf("module %s: set %s: %w", c.moduleName, resourceID, err)
	}

	if resp.GetError() != "" {
		return fmt.Errorf("module %s: set %s: %s", c.moduleName, resourceID, resp.GetError())
	}
	if !resp.GetApplied() {
		return fmt.Errorf("module %s: set %s: module reported not applied", c.moduleName, resourceID)
	}

	return nil
}
