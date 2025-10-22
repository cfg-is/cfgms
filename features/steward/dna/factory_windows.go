//go:build windows

package dna

// Platform-specific factory implementations for Windows
func newPlatformHardwareCollector() HardwareCollector {
	return &WindowsHardwareCollector{}
}

func newPlatformSoftwareCollector() SoftwareCollector {
	return &WindowsSoftwareCollector{}
}

func newPlatformNetworkCollector() NetworkCollector {
	return &WindowsNetworkCollector{}
}

func newPlatformSecurityCollector() SecurityCollector {
	return &WindowsSecurityCollector{}
}
