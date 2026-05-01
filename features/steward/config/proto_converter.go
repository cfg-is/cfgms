// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package config provides conversion between Go structs and protobuf messages
package config

import (
	"fmt"
	"time"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"google.golang.org/protobuf/types/known/durationpb"
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

	// Secrets: serialise SecretsConfig as a map of string references
	stewardSettings.Secrets = map[string]string{
		"secrets_dir": config.Steward.Secrets.SecretsDir,
		"provider":    config.Steward.Secrets.Provider,
	}

	// ConvergeInterval: Go duration string → proto Duration
	if config.Steward.ConvergeInterval != "" {
		d, err := time.ParseDuration(config.Steward.ConvergeInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid converge_interval %q: %w", config.Steward.ConvergeInterval, err)
		}
		stewardSettings.ConvergeInterval = durationpb.New(d)
	}

	// ScriptSigning
	ss := config.Steward.ScriptSigning
	protoSS := &controller.ScriptSigningConfig{
		Policy:        string(ss.Policy),
		TrustMode:     string(ss.TrustMode),
		AllowPublicCa: ss.AllowPublicCA,
		ScriptRepoUrl: ss.ScriptRepoURL,
	}
	for _, key := range ss.TrustedKeys {
		protoSS.TrustedKeys = append(protoSS.TrustedKeys, &controller.TrustedKeyRef{
			Name:         key.Name,
			Thumbprint:   key.Thumbprint,
			PublicKeyRef: key.PublicKeyRef,
		})
	}
	stewardSettings.ScriptSigning = protoSS

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

	// Secrets: reconstruct SecretsConfig from the proto map
	if proto.Steward.Secrets != nil {
		config.Steward.Secrets = SecretsConfig{
			SecretsDir: proto.Steward.Secrets["secrets_dir"],
			Provider:   proto.Steward.Secrets["provider"],
		}
	}

	// ConvergeInterval: proto Duration → Go duration string
	if proto.Steward.ConvergeInterval != nil {
		d := proto.Steward.ConvergeInterval.AsDuration()
		config.Steward.ConvergeInterval = d.String()
	}

	// ScriptSigning
	if proto.Steward.ScriptSigning != nil {
		ps := proto.Steward.ScriptSigning
		sc := ScriptSigningConfig{
			Policy:        ScriptSigningPolicy(ps.Policy),
			TrustMode:     ScriptTrustMode(ps.TrustMode),
			AllowPublicCA: ps.AllowPublicCa,
			ScriptRepoURL: ps.ScriptRepoUrl,
		}
		for _, key := range ps.TrustedKeys {
			sc.TrustedKeys = append(sc.TrustedKeys, TrustedKeyRef{
				Name:         key.Name,
				Thumbprint:   key.Thumbprint,
				PublicKeyRef: key.PublicKeyRef,
			})
		}
		config.Steward.ScriptSigning = sc
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
