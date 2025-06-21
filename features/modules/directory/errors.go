package directory

import "errors"

var (
	// ErrInvalidPath is returned when the path is invalid
	ErrInvalidPath = errors.New("invalid path")

	// ErrPermissionDenied indicates insufficient permissions to perform the operation
	ErrPermissionDenied = errors.New("permission denied")

	// ErrNotADirectory is returned when the path exists but is not a directory
	ErrNotADirectory = errors.New("path exists but is not a directory")

	// ErrRecursiveRequired is returned when parent directories don't exist and recursive is false
	ErrRecursiveRequired = errors.New("parent directories don't exist and recursive is false")

	// ErrInvalidOwner is returned when the specified owner does not exist
	ErrInvalidOwner = errors.New("invalid owner")

	// ErrInvalidGroup is returned when the specified group does not exist
	ErrInvalidGroup = errors.New("invalid group")

	// ErrInvalidPermissions is returned when the specified permissions are invalid
	ErrInvalidPermissions = errors.New("invalid permissions")
)
