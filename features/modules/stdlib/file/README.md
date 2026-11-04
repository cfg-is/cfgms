# File Module

For resource fields, required `allowed_base_path`, platform behavior and examples,
use the [file operator reference](../../../../docs/modules/file.md).

The local implementation and tests own path validation, content comparison and
permission handling. Implementations use the shared [Go Module/ConfigState
contract](../../module.go); the Go interface is Get/Set, with comparison performed
by the steward. The separate [gRPC contract](../../../../docs/architecture/modules/interface.md)
defines wire lifecycle operations.
