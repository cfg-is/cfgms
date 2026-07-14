// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"fmt"
	"strings"
	"text/template"
)

// renderStepString renders a Go template string against workflow variables.
//
// Security scope: the renderer uses only Go's built-in template functions
// (index, ne, eq, and, or, not, len, etc.) — no custom functions are registered,
// so the template cannot call arbitrary Go code. This matches the CFGMS threat
// model where step content must be declared and non-composable.
//
// missingkey=error ensures that any {{ .var }} referencing a variable that is
// not in the execution map returns an explicit error rather than silently
// producing an empty string (AC1).
func renderStepString(s string, vars map[string]interface{}) (string, error) {
	if !strings.Contains(s, "{{") {
		return s, nil
	}

	tmpl, err := template.New("step").Option("missingkey=error").Parse(s)
	if err != nil {
		return "", fmt.Errorf("template parse error: %w", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, vars); err != nil {
		return "", fmt.Errorf("template render error: %w", err)
	}

	return buf.String(), nil
}

// renderStringMap renders each value in a map through renderStepString.
// Keys are not rendered. Returns the first render error encountered.
func renderStringMap(m map[string]string, vars map[string]interface{}) (map[string]string, error) {
	if len(m) == 0 {
		return m, nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		rendered, err := renderStepString(v, vars)
		if err != nil {
			return nil, fmt.Errorf("header/param %q: %w", k, err)
		}
		out[k] = rendered
	}
	return out, nil
}

// renderHTTPConfig returns a shallow copy of cfg with all string fields rendered
// through the template engine. The original cfg is not mutated.
func renderHTTPConfig(cfg *HTTPConfig, vars map[string]interface{}) (*HTTPConfig, error) {
	if cfg == nil {
		return nil, nil
	}
	copy := *cfg

	var err error
	if copy.URL, err = renderStepString(cfg.URL, vars); err != nil {
		return nil, fmt.Errorf("http.url: %w", err)
	}
	if copy.Method, err = renderStepString(cfg.Method, vars); err != nil {
		return nil, fmt.Errorf("http.method: %w", err)
	}
	if copy.Headers, err = renderStringMap(cfg.Headers, vars); err != nil {
		return nil, fmt.Errorf("http.headers: %w", err)
	}

	// Render body only when it is a string.
	if bodyStr, ok := cfg.Body.(string); ok {
		rendered, err := renderStepString(bodyStr, vars)
		if err != nil {
			return nil, fmt.Errorf("http.body: %w", err)
		}
		copy.Body = rendered
	}

	// Render auth string fields.
	if cfg.Auth != nil {
		authCopy := *cfg.Auth
		if authCopy.BearerToken, err = renderStepString(cfg.Auth.BearerToken, vars); err != nil {
			return nil, fmt.Errorf("http.auth.bearer_token: %w", err)
		}
		if authCopy.APIKey, err = renderStepString(cfg.Auth.APIKey, vars); err != nil {
			return nil, fmt.Errorf("http.auth.api_key: %w", err)
		}
		if authCopy.APIKeyHeader, err = renderStepString(cfg.Auth.APIKeyHeader, vars); err != nil {
			return nil, fmt.Errorf("http.auth.api_key_header: %w", err)
		}
		if authCopy.Username, err = renderStepString(cfg.Auth.Username, vars); err != nil {
			return nil, fmt.Errorf("http.auth.username: %w", err)
		}
		if authCopy.Password, err = renderStepString(cfg.Auth.Password, vars); err != nil {
			return nil, fmt.Errorf("http.auth.password: %w", err)
		}
		if authCopy.CustomHeaders, err = renderStringMap(cfg.Auth.CustomHeaders, vars); err != nil {
			return nil, fmt.Errorf("http.auth.custom_headers: %w", err)
		}
		copy.Auth = &authCopy
	}

	return &copy, nil
}

// renderAPIConfig returns a shallow copy of cfg with all string fields rendered
// through the template engine.
func renderAPIConfig(cfg *APIConfig, vars map[string]interface{}) (*APIConfig, error) {
	if cfg == nil {
		return nil, nil
	}
	copy := *cfg

	var err error
	if copy.Provider, err = renderStepString(cfg.Provider, vars); err != nil {
		return nil, fmt.Errorf("api.provider: %w", err)
	}
	if copy.Service, err = renderStepString(cfg.Service, vars); err != nil {
		return nil, fmt.Errorf("api.service: %w", err)
	}
	if copy.Operation, err = renderStepString(cfg.Operation, vars); err != nil {
		return nil, fmt.Errorf("api.operation: %w", err)
	}

	// Render string values in the parameters map.
	if len(cfg.Parameters) > 0 {
		params := make(map[string]interface{}, len(cfg.Parameters))
		for k, v := range cfg.Parameters {
			if s, ok := v.(string); ok {
				rendered, err := renderStepString(s, vars)
				if err != nil {
					return nil, fmt.Errorf("api.parameters[%q]: %w", k, err)
				}
				params[k] = rendered
			} else {
				params[k] = v
			}
		}
		copy.Parameters = params
	}

	return &copy, nil
}

// renderWebhookConfig returns a shallow copy of cfg with all string fields rendered.
func renderWebhookConfig(cfg *WebhookConfig, vars map[string]interface{}) (*WebhookConfig, error) {
	if cfg == nil {
		return nil, nil
	}
	copy := *cfg

	var err error
	if copy.URL, err = renderStepString(cfg.URL, vars); err != nil {
		return nil, fmt.Errorf("webhook.url: %w", err)
	}
	if copy.Method, err = renderStepString(cfg.Method, vars); err != nil {
		return nil, fmt.Errorf("webhook.method: %w", err)
	}
	if copy.Headers, err = renderStringMap(cfg.Headers, vars); err != nil {
		return nil, fmt.Errorf("webhook.headers: %w", err)
	}
	if payloadStr, ok := cfg.Payload.(string); ok {
		rendered, err := renderStepString(payloadStr, vars)
		if err != nil {
			return nil, fmt.Errorf("webhook.payload: %w", err)
		}
		copy.Payload = rendered
	}

	return &copy, nil
}
