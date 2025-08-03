//go:build linux

package dna

// Platform-specific factory implementations for Linux
func newPlatformHardwareCollector() HardwareCollector {
	return &LinuxHardwareCollector{}
}

func newPlatformSoftwareCollector() SoftwareCollector {
	return &LinuxSoftwareCollector{}
}

func newPlatformNetworkCollector() NetworkCollector {
	return &LinuxNetworkCollector{}
}

func newPlatformSecurityCollector() SecurityCollector {
	return &LinuxSecurityCollector{}
}