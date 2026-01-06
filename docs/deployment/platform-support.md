# Platform Support

CFGMS is designed as a cross-platform configuration management system that supports diverse infrastructure environments. This document outlines the officially supported platforms and architectures.

## Supported Platforms

### Steward (Agent) Support

The CFGMS Steward is designed for broad cross-platform deployment to managed endpoints:

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| **Linux** | AMD64 (x86_64) | ✅ Fully Supported | Primary development platform |
| **Linux** | ARM64 (aarch64) | ✅ Fully Supported | Raspberry Pi, AWS Graviton, etc. |
| **Windows** | AMD64 (x86_64) | ✅ Fully Supported | Windows 10, 11, Server 2019+ |
| **Windows** | ARM64 | ✅ Fully Supported | Surface Pro X, Windows on ARM |
| **macOS** | ARM64 (M series) | ✅ Fully Supported | Apple Silicon Macs (M1, M2, M3+) |

### Controller Support

The CFGMS Controller is designed for infrastructure deployment:

| Platform | Architecture | Status | Use Case |
|----------|-------------|--------|----------|
| **Linux** | AMD64 (x86_64) | ✅ Primary Target | Production deployments, containers |
| **Windows** | AMD64 (x86_64) | ✅ Supported | Development, testing, hybrid environments |

## Platform-Specific Features

### Cross-Platform Steward Capabilities

#### Linux & macOS (Unix-like)

- **System Information**: Native syscall-based hardware and software collection
- **Package Management**: Native package manager integration (apt, yum, brew, etc.)
- **Process Management**: Full Unix process control and monitoring
- **File System**: POSIX-compliant file and directory management with ownership/permissions
- **Network**: Native network interface and routing table access
- **Security**: User/group management, SSH key handling, firewall configuration

#### Windows

- **System Information**: WMI and PowerShell-based hardware and software collection
- **Package Management**: Chocolatey, Winget, and Windows Store app management
- **Process Management**: Windows service management and process control
- **File System**: NTFS-aware file management with Windows ACLs
- **Network**: Windows networking stack integration
- **Security**: Windows user management, Group Policy integration

### Controller Platform Features

#### Linux (Primary Target)

- **Container Ready**: Optimized for Docker and Kubernetes deployments
- **System Integration**: Native systemd service integration
- **High Availability**: Production-ready clustering and failover
- **Performance**: Optimized for high-throughput steward management (50k+ endpoints)

#### Windows (Development/Hybrid)

- **Service Integration**: Windows Service support for production deployment
- **Development**: Full development environment support
- **Hybrid Environments**: Mixed Windows/Linux infrastructure management

## Deployment Architectures

### Enterprise MSP Deployment

```
┌─────────────────┐    ┌──────────────────────────────────────┐
│   Controller    │    │            Managed Endpoints         │
│   (Linux)       │────┤                                      │
│                 │    │  ┌─────────┐ ┌─────────┐ ┌─────────┐ │
│ - Ubuntu 22.04  │    │  │ Linux   │ │ Windows │ │ macOS   │ │
│ - Docker/K8s    │    │  │ Steward │ │ Steward │ │ Steward │ │
│ - High Perf.    │    │  └─────────┘ └─────────┘ └─────────┘ │
└─────────────────┘    └──────────────────────────────────────┘
```

### Development Environment

```
┌─────────────────────────────────────────────────────────────┐
│              Developer Workstation                          │
│                                                             │
│  ┌─────────────┐          ┌─────────────┐                  │
│  │ Controller  │   mTLS   │  Steward    │                  │
│  │ (Any OS)    │ ◄────────┤ (Local OS)  │                  │
│  │             │          │             │                  │
│  │ - Windows   │          │ - Same OS   │                  │
│  │ - macOS     │          │ - Testing   │                  │
│  │ - Linux     │          │             │                  │
│  └─────────────┘          └─────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

## Build and Deployment

### Cross-Platform Building

CFGMS supports native cross-compilation for all target platforms:

```bash
# Steward builds for all supported platforms
make build-steward-linux-amd64    # Linux x86_64
make build-steward-linux-arm64    # Linux ARM64
make build-steward-windows-amd64  # Windows x86_64
make build-steward-windows-arm64  # Windows ARM64
make build-steward-darwin-arm64   # macOS Apple Silicon

# Controller builds
make build-controller-linux-amd64   # Linux x86_64 (primary)
make build-controller-windows-amd64 # Windows x86_64 (development)
```

### GitHub Actions CI/CD

The project includes automated builds and testing for all supported platforms:

- **Linux**: ubuntu-latest runners for primary testing
- **Windows**: windows-latest runners for Windows-specific validation
- **macOS**: macos-latest runners for Apple Silicon compatibility
- **Cross-compilation**: All platforms built and tested in CI pipeline

## Platform-Specific Installation

### Linux Steward

```bash
# Download and install
wget https://releases.cfgms.io/v0.3.0/cfgms-steward-linux-amd64
chmod +x cfgms-steward-linux-amd64
sudo mv cfgms-steward-linux-amd64 /usr/local/bin/cfgms-steward

# systemd service (optional)
sudo systemctl enable cfgms-steward
sudo systemctl start cfgms-steward
```

### Windows Steward

```powershell
# Download and install
Invoke-WebRequest -Uri "https://releases.cfgms.io/v0.3.0/cfgms-steward-windows-amd64.exe" -OutFile "cfgms-steward.exe"

# Windows Service (optional)
sc create CFGMSSteward binPath="C:\Program Files\CFGMS\cfgms-steward.exe"
sc start CFGMSSteward
```

### macOS Steward

```bash
# Download and install
curl -L https://releases.cfgms.io/v0.3.0/cfgms-steward-darwin-arm64 -o cfgms-steward
chmod +x cfgms-steward
sudo mv cfgms-steward /usr/local/bin/

# launchd service (optional)
sudo launchctl load /Library/LaunchDaemons/com.cfgms.steward.plist
```

## Performance Characteristics

### Resource Usage by Platform

| Platform | CPU Usage | Memory Usage | Disk I/O | Network |
|----------|-----------|--------------|----------|---------|
| Linux    | ~1% idle, ~5% active | 50-80 MB | Minimal | mTLS optimized |
| Windows  | ~2% idle, ~8% active | 60-100 MB | WMI overhead | mTLS optimized |
| macOS    | ~1% idle, ~6% active | 55-85 MB | Minimal | mTLS optimized |

### Scale Testing Results

- **Linux Controller**: Tested with 50,000+ concurrent stewards
- **Cross-platform Stewards**: Validated across mixed infrastructure environments
- **Network Efficiency**: mTLS connection pooling reduces overhead across platforms

## Security Considerations

### Platform Security Features

#### Linux

- **Process Isolation**: Full namespace and cgroup support
- **File Permissions**: POSIX ACL enforcement
- **Network Security**: iptables/netfilter integration
- **Certificate Management**: Native OpenSSL integration

#### Windows

- **Process Isolation**: Windows job objects and process isolation
- **File Permissions**: NTFS ACL enforcement
- **Network Security**: Windows Firewall integration
- **Certificate Management**: Windows Certificate Store integration

#### macOS

- **Process Isolation**: Sandbox and entitlements support
- **File Permissions**: Extended attributes and ACL support
- **Network Security**: pfctl firewall integration
- **Certificate Management**: Keychain integration

## Troubleshooting

### Common Platform Issues

#### Linux

- **Permission Errors**: Ensure steward runs with appropriate privileges for resource management
- **Systemd Integration**: Check service file permissions and user context

#### Windows

- **WMI Access**: Verify WMI service is running and accessible
- **PowerShell Execution**: Check PowerShell execution policy settings
- **Service Installation**: Require Administrator privileges for service installation

#### macOS

- **Gatekeeper**: Code signing may be required for distribution
- **System Permissions**: Grant necessary permissions in System Preferences > Security
- **Launchd Services**: Ensure proper plist format and permissions

### Platform-Specific Logging

Each platform logs to appropriate system locations:

- **Linux**: `/var/log/cfgms/` or systemd journal
- **Windows**: Windows Event Log and `C:\ProgramData\CFGMS\logs\`
- **macOS**: System log and `/usr/local/var/log/cfgms/`

## Future Platform Support

### Planned Additions

- **Linux ARM32**: Raspberry Pi and embedded device support
- **FreeBSD**: Advanced networking appliance support
- **Container Platforms**: Native Kubernetes operator deployment

### Community Contributions

Platform support contributions are welcome. See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on adding new platform support.
