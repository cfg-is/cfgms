// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package config provides conversion between Go structs and protobuf messages
package config

import (
	"fmt"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"google.golang.org/protobuf/types/known/structpb"
)

// ToProto converts Go StewardConfig to protobuf StewardConfig
func ToProto(config *StewardConfig) (*controller.StewardConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	// Convert steward settings
	stewardSettings := &controller.StewardSettings{
		Id:   config.Steward.ID,
		Mode: string(config.Steward.Mode),
		Logging: &controller.LoggingConfig{
			Level:  config.Steward.Logging.Level,
			Format: config.Steward.Logging.Format,
		},
		ErrorHandling: &controller.ErrorHandlingConfig{
			ModuleLoadFailure:  string(config.Steward.ErrorHandling.ModuleLoadFailure),
			ResourceFailure:    string(config.Steward.ErrorHandling.ResourceFailure),
			ConfigurationError: string(config.Steward.ErrorHandling.ConfigurationError),
		},
	}

	if config.Steward.ModulePaths != nil {
		stewardSettings.ModulePaths = config.Steward.ModulePaths
	}

	// Convert resources
	resources := make([]*controller.ResourceConfig, len(config.Resources))
	for i, res := range config.Resources {
		// Convert config map to protobuf Struct
		configStruct, err := structpb.NewStruct(res.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to convert resource config to struct: %w", err)
		}

		resources[i] = &controller.ResourceConfig{
			Name:   res.Name,
			Module: res.Module,
			Config: configStruct,
		}
	}

	return &controller.StewardConfig{
		Steward:   stewardSettings,
		Resources: resources,
		Modules:   config.Modules,
	}, nil
}

// FromProto converts protobuf StewardConfig to Go StewardConfig
func FromProto(proto *controller.StewardConfig) (*StewardConfig, error) {
	if proto == nil {
		return nil, fmt.Errorf("proto config is nil")
	}

	config := &StewardConfig{
		Steward: StewardSettings{
			ID:          proto.Steward.Id,
			Mode:        OperationMode(proto.Steward.Mode),
			ModulePaths: proto.Steward.ModulePaths,
		},
		Modules: proto.Modules,
	}

	// Convert logging settings
	if proto.Steward.Logging != nil {
		config.Steward.Logging = LoggingConfig{
			Level:  proto.Steward.Logging.Level,
			Format: proto.Steward.Logging.Format,
		}
	}

	// Convert error handling settings
	if proto.Steward.ErrorHandling != nil {
		config.Steward.ErrorHandling = ErrorHandlingConfig{
			ModuleLoadFailure:  ErrorAction(proto.Steward.ErrorHandling.ModuleLoadFailure),
			ResourceFailure:    ErrorAction(proto.Steward.ErrorHandling.ResourceFailure),
			ConfigurationError: ErrorAction(proto.Steward.ErrorHandling.ConfigurationError),
		}
	}

	// Convert resources
	config.Resources = make([]ResourceConfig, len(proto.Resources))
	for i, res := range proto.Resources {
		// Convert protobuf Struct to map
		configMap := res.Config.AsMap()

		config.Resources[i] = ResourceConfig{
			Name:   res.Name,
			Module: res.Module,
			Config: configMap,
		}
	}

	return config, nil
}
