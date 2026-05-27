# CFGMS Connectivity Troubleshooting Guide

**Last Updated**: 2026-03-25 (updated for gRPC-over-QUIC transport, Phase 10.12)
**CFGMS Version**: v0.9.x+

## Overview

This guide helps diagnose and resolve connectivity issues in CFGMS deployments. As of Phase 10.11,
all controller-steward communication uses the unified **gRPC-over-QUIC transport** on port 4433 (UDP).
The previous transport (port 1883) and standalone QUIC data plane have been removed.

## Table of Contents

1. [Quick Diagnostic](#quick-diagnostic)
2. [Transport Connectivity Issues](#transport-connectivity-issues)
3. [TLS and mTLS Issues](#tls-and-mtls-issues)
4. [gRPC Stream Issues](#grpc-stream-issues)
5. [Config Sync Issues](#config-sync-issues)
6. [Reconnection Issues](#reconnection-issues)
7. [Performance Issues](#performance-issues)
8. [Advanced Debugging](#advanced-debugging)

## Quick Diagnostic

**Run this first to identify the problem area:**

```bash
# 1. Check all containers are running
docker ps

# Expected output should show:
# - controller (or controller-standalone)
# - steward (or steward-standalone)
# (No separate broker required)

# 2. Check for errors in logs
docker compose logs | grep -i error

# 3. Run E2E diagnostic test
cd test/integration/transport
go test -v -run TestE2EFlowDiagnostic

# This will show exactly which phase fails
```

### Diagnostic Test Output Interpretation

```
🌐 Phase 1 PASS: REST API accessible
📤 Phase 2 PASS: Configuration uploaded
🔗 Phase 3 PASS: Transport connection established
🔄 Phase 4 PASS: Config sync command delivered
📥 Phase 5 PASS: Status report received
⚙️  Phase 6 PASS: Module executed and file created
```

**If Phase 1 fails**: [REST API Issues](#rest-api-issues)
**If Phase 2 fails**: [Config Upload Issues](#config-sync-issues)
**If Phase 3 fails**: [Transport Connectivity Issues](#transport-connectivity-issues)
**If Phase 4–5 fail**: [gRPC Stream Issues](#grpc-stream-issues)
**If Phase 6 fails**: Module execution issues (check steward logs)

## Transport Connectivity Issues

The transport layer uses **QUIC (UDP) on port 4433** for all controller-steward communication.
Common causes of transport failures:

### Issue: "Connection refused on port 4433"

**Symptoms**:
- Steward logs show "failed to connect to controller transport"
- `nc -zuv controller-vm 4433` reports no response

**Root Causes & Solutions**:

**1. Controller Not Running**

```bash
# Check controller status
systemctl status cfgms-controller
# or for Docker:
docker ps | grep controller

# Start if not running
systemctl start cfgms-controller
```

**2. Port Not Listening**

```bash
# Check UDP port 4433 is listening
sudo ss -ulnp | grep 4433
# or:
sudo netstat -ulnp | grep 4433

# Expected: controller process bound to 0.0.0.0:4433

# If not listening, check controller config:
grep -A5 "transport:" /etc/cfgms/controller.cfg
# listen_addr must be "0.0.0.0:4433" (not 127.0.0.1)
```

**3. Firewall Blocking UDP**

```bash
# QUIC uses UDP — many firewalls default to TCP-only
sudo ufw status
sudo ufw allow 4433/udp

# Or iptables:
sudo iptables -A INPUT -p udp --dport 4433 -j ACCEPT
```

**4. Container Networking (Docker)**

```bash
# Verify containers are on same network
docker network inspect cfgms_default

# Check port mapping
docker ps --format "table {{.Names}}\t{{.Ports}}"
# controller should show: 0.0.0.0:4433->4433/udp
```

### Issue: "Transport connection timeout"

**Symptoms**:
- Connection attempts hang without response
- No entries in controller logs for attempted connection

**Diagnostic**:

```bash
# From steward host, test UDP reachability:
# (nc -zu is unreliable for QUIC; check controller logs instead)
docker logs controller | grep "transport\|QUIC\|connection"

# Check steward logs for where the timeout occurs
docker logs steward-standalone | grep "transport\|dial\|timeout"
```

## TLS and mTLS Issues

All transport connections use mTLS — both sides present certificates. Every failure to connect
is ultimately a TLS or certificate issue unless the port is unreachable.

### Issue: "x509: certificate signed by unknown authority"

**Symptoms**:
- Steward cannot complete TLS handshake
- Logs show "certificate signed by unknown authority" or "x509 verification failed"

**Solutions**:

```bash
# 1. Verify CA fingerprints match on both sides
docker exec controller openssl x509 -in /etc/cfgms/certs/ca.pem -noout -fingerprint -sha256
docker exec steward-standalone openssl x509 -in /etc/cfgms/certs/ca.pem -noout -fingerprint -sha256
# Fingerprints MUST be identical

# 2. If mismatched, steward needs to re-register
docker compose restart steward-standalone
# Steward will re-register and obtain certificates from current CA

# 3. Check controller logs for certificate generation:
docker logs controller | grep "Certificate manager initialized"
docker logs controller | grep "Generated.*certificate"
```

### Issue: "certificate has expired" or "certificate not yet valid"

**Symptoms**:
- TLS errors mentioning expiration or validity dates
- Connections fail immediately after TLS ClientHello

**Solutions**:

```bash
# 1. Check certificate validity dates
docker exec controller openssl x509 -in /etc/cfgms/certs/server.pem -noout -dates

# 2. Verify system clocks match (QUIC is sensitive to clock skew)
docker exec controller date
docker exec steward-standalone date
date  # Host system

# 3. Sync clocks if drifted:
sudo timedatectl set-ntp true

# 4. If certificates genuinely expired, regenerate:
docker compose down
# Remove cert storage (backs up first)
docker compose up -d
```

### Issue: "TLS handshake failure" (client certificate rejected)

**Symptoms**:
- Controller logs show "TLS: client certificate rejected"
- Steward logs show "bad certificate" or "handshake failure"

**Diagnostic**:

```bash
# Check steward has valid client certificate
docker exec steward-standalone ls -la /etc/cfgms/certs/
# Expected: client.pem, client-key.pem, ca.pem

# Verify client cert was issued by controller CA
docker exec steward-standalone openssl verify \
  -CAfile /etc/cfgms/certs/ca.pem \
  /etc/cfgms/certs/client.pem
# Expected: client.pem: OK
```

## gRPC Stream Issues

Once the QUIC connection is established, gRPC streams carry the actual calls. These can fail
independently of the underlying transport.

### Issue: "gRPC stream reset" or "stream broken"

**Symptoms**:
- Steward connects but commands are not delivered
- Controller logs show "stream reset" or "unexpected EOF"
- Heartbeats stop after initial connection

**Solutions**:

```bash
# 1. Enable debug logging to see gRPC frame details
CFGMS_LOG_LEVEL=debug docker compose up -d controller steward-standalone

docker logs -f controller | grep -i "grpc\|stream"
docker logs -f steward-standalone | grep -i "grpc\|stream"

# 2. Check keepalive settings — streams break if keepalive is too aggressive
# In controller.cfg:
# transport:
#   keepalive_period: 30s   # increase if streams reset frequently
#   idle_timeout: 5m        # increase for slow networks

# 3. Check for firewall stateful rules that expire UDP "connections"
# QUIC uses long-lived UDP flows — some NAT/firewall rules close them after 30s
# Solution: Configure longer UDP timeout in firewall, or enable keepalive probes
```

### Issue: "rpc error: code = Unavailable"

**Symptoms**:
- gRPC calls fail with code = Unavailable
- Usually happens after idle periods or network blips

**Solutions**:

```bash
# This typically means the underlying QUIC connection was lost
# The steward should automatically reconnect — check reconnection logs:
docker logs steward-standalone | grep -i "reconnect\|retry\|backoff"

# If reconnection is not happening:
docker logs steward-standalone | grep -i "error\|failed" | tail -20

# Manual trigger: restart steward (will reconnect cleanly)
docker compose restart steward-standalone
```

## Config Sync Issues

### Issue: "Config uploaded but never applied by steward"

**Symptoms**:
- Config upload via REST API returns 200
- Steward never applies the config
- No convergence activity in steward logs

**Diagnostic Steps**:

```bash
# 1. Verify config was stored
docker exec controller ls -la /data/git-storage/

# 2. Check steward received sync command via gRPC control plane
docker logs steward-standalone | grep "sync_config\|SyncConfig"

# 3. Check controller sent the command
docker logs controller | grep "SyncConfig\|dispatch.*steward"

# 4. Verify steward is connected (shows up in heartbeat logs)
docker logs controller | grep "heartbeat\|steward.*connected"
```

**Solutions**:

**A. Trigger manual sync via REST API**:
```bash
# Force config push for a specific steward
curl -X POST http://controller:9080/api/v1/stewards/$STEWARD_ID/sync \
  -H "Authorization: Bearer $API_KEY"
```

**B. Reconnect steward**:
```bash
docker compose restart steward-standalone
# On reconnect, steward automatically checks for pending configs
```

### Issue: "Signature verification failed"

**Symptoms**:
- Steward receives config but rejects it
- Logs show "signature verification failed" or "signer certificate mismatch"

**Solution**:
```bash
# Verify controller's signing certificate serial is consistent
docker logs controller | grep "signerCertSerial\|config.*signer"

# If mismatch, reinitialize controller (extreme case - backs up first)
# More likely: steward has stale signer cert from old registration
docker compose restart steward-standalone
```

## Reconnection Issues

### Issue: "Steward disconnects and does not reconnect"

**Symptoms**:
- Steward initially connects, then disconnects
- Does not attempt to reconnect after the first failure
- Controller logs show steward offline indefinitely

**Diagnostic**:

```bash
# Check steward reconnection behavior
docker logs steward-standalone | grep -E "reconnect|backoff|retry"

# Check for fatal errors that prevent reconnection
docker logs steward-standalone | grep -E "fatal|panic|exit"
```

**Solutions**:

```bash
# 1. Check backoff configuration — steward uses exponential backoff
# Default: starts at 1s, max 5min, indefinite retries
# Controller must be reachable for reconnection to succeed

# 2. Verify controller is healthy
curl http://controller:9080/api/v1/health

# 3. Check for certificate expiry preventing reconnection
docker exec steward-standalone openssl x509 -in /etc/cfgms/certs/client.pem -noout -dates
# If expired, steward cannot reconnect — must re-register
```

### Issue: "High reconnection rate / flapping"

**Symptoms**:
- Steward connects and disconnects repeatedly
- Controller logs show rapid connect/disconnect cycle
- Performance degraded due to TLS handshake overhead

**Solutions**:

```bash
# 1. Increase keepalive to reduce false disconnect detection
# transport:
#   keepalive_period: 60s  # was 30s

# 2. Check network stability between steward and controller
ping -c 20 controller-vm
# High packet loss or latency causes QUIC connection failures

# 3. Check for resource exhaustion on controller
docker stats controller
# If CPU > 90%, connection handling degrades — scale up or reduce max_connections
```

## Performance Issues

### Issue: "Config sync takes > 10 seconds"

**Target**: Config sync should complete in < 5 seconds for small configs.

**Diagnostic**:

```bash
# Run transport E2E diagnostic with timing
cd test/integration/transport
go test -v -run TestE2EFlowDiagnostic | grep "Phase.*PASS"

# Check resource usage
docker stats controller steward-standalone

# Trace slow operations in logs
docker logs controller | grep -E "took|duration|elapsed|slow"
```

**Solutions**:

```bash
# 1. Check disk I/O (for git storage — commit is on critical path)
docker exec controller df -h
docker exec controller iostat -x 1 5

# 2. Check network round-trip time
docker exec steward-standalone ping -c 5 controller-standalone

# 3. Scale max_connections if controller is overloaded
# transport:
#   max_connections: 10000  # default; reduce if CPU-bound
```

## Advanced Debugging

### Enable Debug Logging

```bash
# Controller
CFGMS_LOG_LEVEL=debug docker compose up -d controller
docker logs -f controller | grep -i "transport\|grpc\|quic"

# Steward
CFGMS_LOG_LEVEL=debug docker compose up -d steward-standalone
docker logs -f steward-standalone | grep -i "transport\|grpc\|quic"
```

### Packet Capture (QUIC/UDP)

```bash
# Capture QUIC traffic on port 4433
sudo tcpdump -i any udp port 4433 -w /tmp/quic-capture.pcap

# In another terminal, trigger a test
cd test/integration/transport
go test -v -run TestConfigSync

# Stop tcpdump (Ctrl+C)
# Analyze in Wireshark (has QUIC dissector)
wireshark /tmp/quic-capture.pcap
```

### Health Check Endpoints

```bash
# Controller health
curl http://localhost:9080/api/v1/health

# Transport health
curl http://localhost:9080/api/v1/health/transport

# Storage health
curl http://localhost:9080/api/v1/health/storage

# Metrics (if enabled)
curl http://localhost:9080/metrics
```

## Getting Help

If issues persist after following this guide:

1. **Collect diagnostic information**:
   ```bash
   # Run full E2E diagnostic
   cd test/integration/transport
   go test -v -run TestE2EFlowDiagnostic > /tmp/diagnostic.log 2>&1

   # Collect logs
   docker compose logs > /tmp/cfgms-logs.txt

   # System info
   docker version > /tmp/system-info.txt
   uname -a >> /tmp/system-info.txt
   ```

2. **Create GitHub issue** with the above files and a description of the problem.

3. **Check existing issues**: https://github.com/cfg-is/cfgms/issues

## References

- **E2E Testing Guide**: [docs/testing/e2e-testing-guide.md](../testing/e2e-testing-guide.md)
- **Deployment Guide**: [docs/deployment/README.md](../deployment/README.md)
- **Transport Architecture**: [docs/architecture/communication-layer-migration.md](../architecture/communication-layer-migration.md)
