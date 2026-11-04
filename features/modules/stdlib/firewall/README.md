# Firewall Module

The [firewall operator reference](../../../../docs/modules/firewall.md) owns
required rule fields, examples and platform limitations. The current backend is
Linux iptables; other platforms use a stub, so target these resources to Linux.

Developers should inspect [module operations](module.go), the
[Linux executor](executor_linux.go), [non-Linux stub](executor_stub.go) and tests
beside them. Use the shared [Module/ConfigState contract](../../module.go) rather
than copying another interface or operator configuration table here.
