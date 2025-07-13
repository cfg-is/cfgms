package api

import (
	"time"
)

// getCurrentTimestamp returns the current time in UTC
func getCurrentTimestamp() time.Time {
	return time.Now().UTC()
}
