// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package blob_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// envMap returns an environment block in map form; service definitions that
// use the list form yield nil, which is fine for the checks below.
func envMap(n yaml.Node) map[string]string {
	m := map[string]string{}
	if n.Kind != yaml.MappingNode {
		return m
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		m[n.Content[i].Value] = n.Content[i+1].Value
	}
	return m
}

type composeFile struct {
	Services map[string]struct {
		Image       string    `yaml:"image"`
		Environment yaml.Node `yaml:"environment"`
		Ports       []string  `yaml:"ports"`
		Tmpfs       []string  `yaml:"tmpfs"`
		Volumes     []string  `yaml:"volumes"`
		Profiles    []string  `yaml:"profiles"`
		Healthcheck struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
	} `yaml:"services"`
}

// TestComposeS3ServiceDefinition checks, without Docker, that the s3-test
// service in docker-compose.test.yml matches what the blob migrator test and
// the HA controllers expect: a digest-pinned image, the in-network port 9000
// that CFGMS_S3_INSTALLER_ENDPOINT_URL names, the host port 9002 that
// s3TestConfig defaults to, both profiles, and a healthcheck that does not
// depend on curl.
func TestComposeS3ServiceDefinition(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docker-compose.test.yml"))
	if err != nil {
		t.Fatalf("read compose file: %v", err)
	}
	var cf composeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		t.Fatalf("parse compose file: %v", err)
	}

	svc, ok := cf.Services["s3-test"]
	if !ok {
		t.Fatal("docker-compose.test.yml has no s3-test service")
	}
	if !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(svc.Image) {
		t.Errorf("image %q is not pinned by @sha256 digest", svc.Image)
	}
	if strings.Contains(svc.Image, "minio") {
		t.Errorf("image %q is the unpullable minio image", svc.Image)
	}
	if !contains(svc.Ports, "9002:9000") {
		t.Errorf("ports %v do not publish container port 9000 on host port 9002", svc.Ports)
	}
	for _, profile := range []string{"blob-migrate", "ha"} {
		if !contains(svc.Profiles, profile) {
			t.Errorf("profiles %v missing %q", svc.Profiles, profile)
		}
	}
	hc := strings.Join(svc.Healthcheck.Test, " ")
	if hc == "" || strings.Contains(hc, "curl") || !strings.Contains(hc, "9000") {
		t.Errorf("healthcheck %q must probe port 9000 without curl", hc)
	}
	if !strings.Contains(envMap(svc.Environment)["VGW_ARGS"], "--access s3admin --secret s3admin") {
		t.Errorf("VGW_ARGS %q does not set the credentials s3TestConfig defaults to", envMap(svc.Environment)["VGW_ARGS"])
	}

	// The image ships no /data directory, so the posix backend exits at start
	// ("chdir /data: no such file or directory") unless the directory named by
	// VGW_BACKEND_ARG is provided by a tmpfs or volume mount.
	backend := envMap(svc.Environment)["VGW_BACKEND_ARG"]
	if backend == "" {
		t.Error("VGW_BACKEND_ARG is not set")
	} else if !mountsPath(svc.Tmpfs, backend) && !mountsVolume(svc.Volumes, backend) {
		t.Errorf("backend dir %q is not provided by a tmpfs or volume mount (tmpfs %v, volumes %v)", backend, svc.Tmpfs, svc.Volumes)
	}

	for name, s := range cf.Services {
		env := envMap(s.Environment)
		if got := env["CFGMS_S3_INSTALLER_ENDPOINT_URL"]; got != "" && got != "http://s3-test:9000" {
			t.Errorf("service %s endpoint %q does not name s3-test:9000", name, got)
		}
		if key, dep := env["AWS_ACCESS_KEY_ID"]; dep && key != "s3admin" {
			t.Errorf("service %s AWS_ACCESS_KEY_ID does not match the s3-test credentials", name)
		}
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// mountsPath reports whether a tmpfs entry ("/path" or "/path:opts") targets path.
func mountsPath(entries []string, path string) bool {
	for _, e := range entries {
		if strings.SplitN(e, ":", 2)[0] == path {
			return true
		}
	}
	return false
}

// mountsVolume reports whether a short-syntax volume entry
// ("source:/target[:mode]") targets path.
func mountsVolume(entries []string, path string) bool {
	for _, e := range entries {
		parts := strings.Split(e, ":")
		if len(parts) >= 2 && parts[1] == path {
			return true
		}
	}
	return false
}
