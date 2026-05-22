// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package scriptrelay implements per-execution API relay for library scripts
// with non-empty RequiredAPIScope. The relay opens a unix socket (Linux/macOS)
// or named pipe (Windows) and proxies the script's REST calls over the steward's
// existing mTLS connection to the controller.
package scriptrelay

import "fmt"

// InjectBashPreamble prepends a cfgms_api shell function to content.
// The function reads CFGMS_API_SOCKET and uses curl --unix-socket to relay
// HTTP calls to the controller. Usage: cfgms_api GET /api/v1/runs
func InjectBashPreamble(content, socketPath string) string {
	preamble := fmt.Sprintf(`# cfgms relay preamble — injected by steward
CFGMS_API_SOCKET=%q
cfgms_api() {
  local method="$1"; local path="$2"; shift 2
  curl --silent --unix-socket "$CFGMS_API_SOCKET" \
    -X "$method" \
    -H "Content-Type: application/json" \
    "$@" \
    "http://localhost${path}"
}

`, socketPath)
	return preamble + content
}

// InjectPowerShellPreamble prepends an Invoke-CfgApi function to content.
// The function reads CFGMS_API_SOCKET and uses .NET's System.Net.Sockets.Socket
// directly to send HTTP/1.1 requests over the unix socket path, since
// Invoke-WebRequest does not support unix sockets on all Windows versions.
// CRLF is built with [char]13+[char]10 to avoid backtick characters in the
// Go raw-string literal that wraps this template.
func InjectPowerShellPreamble(content, socketPath string) string {
	preamble := fmt.Sprintf(`# cfgms relay preamble — injected by steward
$env:CFGMS_API_SOCKET = %q

function Invoke-CfgApi {
    param(
        [string]$Method = 'GET',
        [string]$Path,
        [string]$Body = ''
    )
    $socketPath = $env:CFGMS_API_SOCKET
    $socket = [System.Net.Sockets.Socket]::new(
        [System.Net.Sockets.AddressFamily]::Unix,
        [System.Net.Sockets.SocketType]::Stream,
        [System.Net.Sockets.ProtocolType]::Unspecified
    )
    $socket.Connect([System.Net.Sockets.UnixDomainSocketEndPoint]::new($socketPath))
    $bodyBytes = if ($Body) { [System.Text.Encoding]::UTF8.GetBytes($Body) } else { [byte[]]@() }
    $crlf = [char]13 + [char]10
    $req = "$Method $Path HTTP/1.1${crlf}Host: cfgms${crlf}Content-Length: $($bodyBytes.Length)${crlf}Content-Type: application/json${crlf}Connection: close${crlf}${crlf}"
    $reqBytes = [System.Text.Encoding]::UTF8.GetBytes($req)
    $null = $socket.Send($reqBytes)
    if ($bodyBytes.Length -gt 0) { $null = $socket.Send($bodyBytes) }
    $buf = [byte[]]::new(65536)
    $received = $socket.Receive($buf)
    $socket.Close()
    $response = [System.Text.Encoding]::UTF8.GetString($buf, 0, $received)
    $sep = $crlf + $crlf
    $parts = $response -split [regex]::Escape($sep), 2
    if ($parts.Length -gt 1) { return $parts[1] }
    return $response
}

`, socketPath)
	return preamble + content
}
