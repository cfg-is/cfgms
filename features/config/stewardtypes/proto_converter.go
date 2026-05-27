// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package stewardtypes

import (
	"fmt"
	"time"

	controller "github.com/cfgis/cfgms/api/proto/controller"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
)

// ToProto converts a StewardConfig to a protobuf StewardConfig.
func ToProto(config *StewardConfig) (*controller.StewardConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

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

	stewardSettings.Secrets = map[string]string{
		"secrets_dir": config.Steward.Secrets.SecretsDir,
		"provider":    config.Steward.Secrets.Provider,
	}

	if config.Steward.ConvergeInterval != "" {
		d, err := time.ParseDuration(config.Steward.ConvergeInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid converge_interval %q: %w", config.Steward.ConvergeInterval, err)
		}
		stewardSettings.ConvergeInterval = durationpb.New(d)
	}

	ss := config.Steward.ScriptSigning
	protoSS := &controller.ScriptSigningConfig{
		Policy:        string(ss.Policy),
		TrustMode:     string(ss.TrustMode),
		AllowPublicCa: ss.AllowPublicCA,
	}
	for _, key := range ss.TrustedKeys {
		protoSS.TrustedKeys = append(protoSS.TrustedKeys, &controller.TrustedKeyRef{
			Name:         key.Name,
			Thumbprint:   key.Thumbprint,
			PublicKeyRef: key.PublicKeyRef,
		})
	}
	stewardSettings.ScriptSigning = protoSS

	resources := make([]*controller.ResourceConfig, len(config.Resources))
	for i, res := range config.Resources {
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

// FromProto converts a protobuf StewardConfig to a StewardConfig.
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

	if proto.Steward.Logging != nil {
		config.Steward.Logging = LoggingConfig{
			Level:  proto.Steward.Logging.Level,
			Format: proto.Steward.Logging.Format,
		}
	}

	if proto.Steward.ErrorHandling != nil {
		config.Steward.ErrorHandling = ErrorHandlingConfig{
			ModuleLoadFailure:  ErrorAction(proto.Steward.ErrorHandling.ModuleLoadFailure),
			ResourceFailure:    ErrorAction(proto.Steward.ErrorHandling.ResourceFailure),
			ConfigurationError: ErrorAction(proto.Steward.ErrorHandling.ConfigurationError),
		}
	}

	if proto.Steward.Secrets != nil {
		config.Steward.Secrets = SecretsConfig{
			SecretsDir: proto.Steward.Secrets["secrets_dir"],
			Provider:   proto.Steward.Secrets["provider"],
		}
	}

	if proto.Steward.ConvergeInterval != nil {
		d := proto.Steward.ConvergeInterval.AsDuration()
		config.Steward.ConvergeInterval = d.String()
	}

	if proto.Steward.ScriptSigning != nil {
		ps := proto.Steward.ScriptSigning
		sc := ScriptSigningConfig{
			Policy:        ScriptSigningPolicy(ps.Policy),
			TrustMode:     ScriptTrustMode(ps.TrustMode),
			AllowPublicCA: ps.AllowPublicCa,
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

	config.Resources = make([]ResourceConfig, len(proto.Resources))
	for i, res := range proto.Resources {
		config.Resources[i] = ResourceConfig{
			Name:   res.Name,
			Module: res.Module,
			Config: res.Config.AsMap(),
		}
	}

	return config, nil
}
