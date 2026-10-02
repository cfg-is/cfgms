# cfg CLI Install Guide

This guide covers installing the `cfg` CLI binary on Linux, macOS, and Windows.

## Linux and macOS

### Quick install (system-wide, requires root)

```bash
make build-cli && sudo bash scripts/install-cfg.sh
```

Installs `cfg` to `/usr/local/bin/cfg`. Verify:

```bash
which cfg
cfg version
```

### Install without root (user-local)

```bash
make build-cli && bash scripts/install-cfg.sh
```

Without root, the script installs to `~/.local/bin/cfg`. If that directory is not on your `PATH`, the script prints a hint:

```
Note: /home/<user>/.local/bin is not on your PATH.
Add it by running:
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

After adding it to your PATH, verify:

```bash
which cfg
cfg version
```

### Custom install prefix

```bash
make build-cli && bash scripts/install-cfg.sh --prefix /opt/cfgms/bin
```

The script creates the prefix directory if it does not exist.

### Re-install

Re-running the install command over an existing binary exits 0 (idempotent).

### Uninstall

For the two default locations (`/usr/local/bin` and `~/.local/bin`):

```bash
make uninstall-cfg
```

For a custom prefix install:

```bash
make uninstall-cfg PREFIX=/opt/cfgms/bin
```

Or manually:

```bash
rm -f /usr/local/bin/cfg
# or, for user-local install:
rm -f ~/.local/bin/cfg
# or, for a custom prefix:
rm -f /opt/cfgms/bin/cfg
```

---

## Windows

On Windows, `make install-cfg` copies `bin\cfg.exe` to `%GOPATH%\bin`.

```
make build-cli && make install-cfg
```

Verify the install:

```powershell
Get-Command cfg
cfg version
```

### PATH setup

`%GOPATH%\bin` must be on your `PATH`. If `Get-Command cfg` fails, add it permanently:

```powershell
setx PATH "%PATH%;%GOPATH%\bin"
```

Then restart your terminal and verify again with `Get-Command cfg`.

---

## Running tests

```bash
make test-install-cfg
```

Runs `scripts/install-cfg-test.sh`, which installs `cfg` to a temporary directory,
verifies `cfg version` exits 0, and confirms that re-install is idempotent.
