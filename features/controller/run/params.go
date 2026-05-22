// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package run

import (
	"fmt"

	script "github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ResolveParams resolves script parameters from three sources in priority order:
//
//  1. runtimeParams — operator-supplied at call time (highest priority)
//  2. DNA bindings — first checks paramPlatformBindings[name] for an admin-configured
//     DNA key path; if the path is absent or not found in stewardDNA, falls back to
//     ScriptParameter.DNAPath resolved against stewardDNA
//  3. Static default — ScriptParameter.Default cast to string
//
// A required parameter (ScriptParameter.Required == true) with no value from any
// source is an error at synthesis time, before the execution is enqueued.
//
// Only parameter names and DNA source key paths are logged; VALUES are never
// emitted because parameters may carry secrets.
func ResolveParams(
	logger logging.Logger,
	scriptMeta *script.ScriptMetadata,
	paramPlatformBindings map[string]string,
	runtimeParams map[string]string,
	stewardDNA map[string]string,
) (map[string]string, error) {
	if scriptMeta == nil {
		result := make(map[string]string, len(runtimeParams))
		for k, v := range runtimeParams {
			result[k] = v
		}
		return result, nil
	}

	resolved := make(map[string]string)

	for _, param := range scriptMeta.Parameters {
		name := param.Name

		// Priority 1: runtime override.
		if _, ok := runtimeParams[name]; ok {
			if logger != nil {
				logger.Debug("param resolved", "param", name, "source", "runtime")
			}
			resolved[name] = runtimeParams[name]
			continue
		}

		// Priority 2a: admin-configured DNA path (ParamPlatformBindings).
		if dnaPath, ok := paramPlatformBindings[name]; ok && dnaPath != "" {
			if v, ok := stewardDNA[dnaPath]; ok {
				if logger != nil {
					logger.Debug("param resolved", "param", name, "source", dnaPath)
				}
				resolved[name] = v
				continue
			}
			// Admin path configured but not present in DNA — fall through to 2b.
		}

		// Priority 2b: author-defined DNA path from ScriptParameter.DNAPath.
		if param.DNAPath != "" {
			if v, ok := stewardDNA[param.DNAPath]; ok {
				if logger != nil {
					logger.Debug("param resolved", "param", name, "source", param.DNAPath)
				}
				resolved[name] = v
				continue
			}
		}

		// Priority 3: static default.
		if param.Default != nil {
			if logger != nil {
				logger.Debug("param resolved", "param", name, "source", "default")
			}
			resolved[name] = fmt.Sprintf("%v", param.Default)
			continue
		}

		// Required parameter with no value from any source is a synthesis-time error.
		if param.Required {
			return nil, fmt.Errorf("required parameter %q has no value from any source (runtime, DNA binding, or default)", name)
		}
	}

	// Carry through runtime params not declared in script metadata.
	for k, v := range runtimeParams {
		if _, already := resolved[k]; !already {
			resolved[k] = v
		}
	}

	return resolved, nil
}
