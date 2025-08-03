//go:build darwin

package dna

// Platform-specific factory implementations for macOS
func newPlatformHardwareCollector() HardwareCollector {
	return &DarwinHardwareCollector{}
}

func newPlatformSoftwareCollector() SoftwareCollector {
	return &DarwinSoftwareCollector{}
}

func newPlatformNetworkCollector() NetworkCollector {
	return &DarwinNetworkCollector{}
}

func newPlatformSecurityCollector() SecurityCollector {
	return &DarwinSecurityCollector{}
}