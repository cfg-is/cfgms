# CFGMS Versioning Policy

This document defines the semantic versioning policy for CFGMS releases.

## Semantic Versioning

CFGMS follows [Semantic Versioning 2.0.0](https://semver.org/) with the format `MAJOR.MINOR.PATCH`:

- **MAJOR** version: Incompatible API or configuration changes
- **MINOR** version: New functionality in a backward-compatible manner
- **PATCH** version: Backward-compatible bug fixes

## Version Format

```
v{MAJOR}.{MINOR}.{PATCH}[-{pre-release}][+{build}]
```

Examples:

- `v0.7.0` - Standard release
- `v1.0.0-rc.1` - Release candidate
- `v1.1.0-beta.1` - Pre-release beta with identifier

## Pre-Release Labels

Pre-release labels (`-alpha`, `-beta`, `-rc`) are **reserved for post-v1.0 releases only**.

**Why no pre-release tags before v1.0?**

The `0.x.x` version range already signals "development/unstable" by SemVer convention. Adding `-alpha` or `-beta` tags to pre-1.0 versions is redundant and adds unnecessary complexity. This approach is common in Go projects and simplifies version management during active development.

**Post-v1.0 Pre-Release Labels:**

| Label | Description | Stability | Example |
|-------|-------------|-----------|---------|
| `rc` | Release candidate, final testing | Near-stable | `v1.1.0-rc.1` |
| `beta` | Feature complete, testing phase | Testing | `v1.2.0-beta.1` |
| `alpha` | Active development, API may change | Unstable | `v2.0.0-alpha.1` |

Pre-release tags are primarily used for:

- Major version transitions (e.g., `v2.0.0-alpha`)
- Significant feature releases requiring community testing (e.g., `v1.5.0-rc.1`)

## Version Support Policy

### Active Support

- **Current Version**: Full support with bug fixes and security patches
- **Previous Minor Version**: Security patches only for 3 months after new minor release

### End of Life

- Versions older than N-2 minor releases are unsupported
- Security vulnerabilities in unsupported versions will be documented but not patched

### Long-Term Support (LTS)

LTS versions will be designated starting with v1.0.0:

- LTS releases receive security patches for 18 months
- Only even minor versions will be designated as LTS (e.g., v1.0, v1.2, v1.4)

## Compatibility Guarantees

### Configuration Compatibility

- **Minor versions**: Configuration files remain backward compatible
- **Major versions**: Migration guides provided for configuration changes
- **Deprecation**: Features deprecated in minor version N, removed in major version N+1

### API Compatibility

- **REST API**: Follows versioned endpoints (e.g., `/api/v1/`)
- **Breaking changes**: Only in major versions with migration documentation
- **Deprecation notices**: Included in CHANGELOG 2 minor versions before removal

### Module Compatibility

- **Module API**: Stable within major version
- **New module capabilities**: Added in minor versions
- **Module deprecation**: Follows standard deprecation policy

## Release Cadence

### Planned Cadence

- **Minor releases**: Every 6-8 weeks during active development
- **Patch releases**: As needed for critical bug fixes
- **Major releases**: When significant breaking changes are required

### Pre-v1.0.0 Development

During alpha/beta development (v0.x.x):
- API changes may occur between minor versions
- Breaking changes documented in CHANGELOG
- Migration guides provided for significant changes

## Version Numbering Examples

### When to Increment MAJOR (X.0.0)

- Incompatible changes to REST API endpoints
- Breaking changes to configuration file format
- Removal of deprecated features
- Major architectural changes affecting deployment

### When to Increment MINOR (0.X.0)

- New features or modules
- New configuration options
- New API endpoints
- Performance improvements
- Deprecation of features (with deprecation notice)

### When to Increment PATCH (0.0.X)

- Bug fixes
- Security patches
- Documentation corrections
- Minor performance fixes

## Git Tags and Releases

### Tag Format

All releases are tagged in git with the format `v{VERSION}`:

```bash
git tag -a v0.7.0 -m "Release v0.7.0"
git push origin v0.7.0
```

### GitHub Releases

Each tagged version will have a corresponding GitHub Release with:
- Release notes summarizing changes
- Link to relevant CHANGELOG entries
- Binary artifacts for supported platforms
- SHA256 checksums for all artifacts

## Build Information

Version information is embedded in binaries at build time:

```go
// Set via ldflags during build
-X github.com/cfgis/cfgms/pkg/version.Version=v0.7.0
-X github.com/cfgis/cfgms/pkg/version.GitCommit=$(git rev-parse --short HEAD)
-X github.com/cfgis/cfgms/pkg/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)
```

Query version information:
```bash
./bin/controller --version
./bin/cfgms-steward --version
./bin/cfg version
```

## Upgrade Process

### Recommended Upgrade Path

1. Review CHANGELOG for breaking changes
2. Test upgrade in non-production environment
3. Backup configuration and data
4. Apply upgrade
5. Verify functionality

### Rollback

All configuration changes through CFGMS support rollback:
- Git-based storage provides full history
- Rollback manager supports previewing and executing rollbacks
- See [Configuration Rollback](../architecture/configuration-management.md) for details

## Related Documentation

- [CHANGELOG.md](../../CHANGELOG.md) - Detailed version history
- [Roadmap](../product/roadmap.md) - Planned features and versions
- [Contributing](../../CONTRIBUTING.md) - How to contribute to releases
