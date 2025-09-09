// Package steward provides temporary protobuf stubs for testing
// This file provides stub implementations of protobuf types to enable testing
// until the protobuf generation issues are resolved.

package steward

import (
	"time"
)

// Temporary stub types for protobuf messages
// These will be replaced once protobuf generation is fixed

type DNA struct {
	Id          string
	Attributes  map[string]string
	LastUpdated time.Time
}

type Status struct {
	Code    StatusCode
	Message string
}

type StatusCode int32

const (
	Status_OK               StatusCode = 0
	Status_ERROR           StatusCode = 1
	Status_NOT_FOUND       StatusCode = 2
	Status_UNAUTHORIZED    StatusCode = 3
	Status_INVALID_REQUEST StatusCode = 4
)

type Credentials struct {
	TenantId    string
	ClientId    string
	Certificate []byte
}

type Token struct {
	AccessToken string
	ExpiresAt   int64
}

type RegisterRequest struct {
	Version     string
	InitialDna  *DNA
	Credentials *Credentials
}

type RegisterResponse struct {
	StewardId string
	Status    *Status
	Token     *Token
}

type HeartbeatRequest struct {
	StewardId string
	Status    string
	Metrics   map[string]string
}