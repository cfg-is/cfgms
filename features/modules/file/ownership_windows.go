//go:build windows

package file

import (
	"os"
	"os/user"
)

// getFileOwnership gets file ownership information on Windows
func getFileOwnership(info os.FileInfo) (string, string, error) {
	// On Windows, just use current user as fallback
	owner := "unknown"
	group := "unknown"

	if current, err := user.Current(); err == nil {
		owner = current.Username
	}

	return owner, group, nil
}
