// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// consume_etw_windows.h — C side of the DEX in-process ETW consumer PoC (#2571).
//
// This is the non-reentrant C-callback architecture (candidate (c) in the story):
// the ETW EventRecordCallback is a pure C function that copies a compact,
// fixed-size header record into a single-producer/single-consumer ring buffer and
// NEVER calls back into Go. A Go goroutine drains the ring. Because the hot
// callback path is C→C only, the native→Go transition (cgocallbackg) that
// corrupts the Go runtime's sudog cache under high-rate ETW callbacks (#2517) is
// never taken.
//
// Only compiled behind the `dexconsume` build tag (throwaway spike; never in the
// production steward path).

#ifndef CFGMS_DEX_CONSUME_H
#define CFGMS_DEX_CONSUME_H

#include <stdint.h>

// CfgmsEvent is the compact per-event record the C callback copies into the ring.
// Header-only: the hot path never decodes (decode is a bounded sample; see below),
// so this stays cheap to produce at high rate. Attribution (pid -> image) happens
// on the Go drain side.
typedef struct CfgmsEvent {
    uint64_t timestamp;    // EVENT_HEADER.TimeStamp (raw QPC/FILETIME units)
    uint32_t pid;          // EVENT_HEADER.ProcessId
    uint32_t tid;          // EVENT_HEADER.ThreadId
    uint16_t provider_idx; // index registered via cfgms_register_provider (0xFFFF = unknown)
    uint16_t event_id;     // EVENT_DESCRIPTOR.Id
    uint8_t  opcode;       // EVENT_DESCRIPTOR.Opcode
    uint8_t  _pad[3];
} CfgmsEvent;

// cfgms_register_provider maps a provider GUID (16 raw bytes, in windows.GUID
// memory order) to a small index the callback stamps into each record. If
// is_decode_target != 0, the callback also TDH-decodes a bounded sample of this
// provider's events (Part 2 proof). Call before cfgms_run.
void cfgms_register_provider(const unsigned char *guid16, int idx, int is_decode_target);

// cfgms_run opens the named real-time session and runs ProcessTrace. It BLOCKS on
// the calling thread (the Go caller runs it on a LockOSThread goroutine) until
// cfgms_stop is called or the session ends. Returns the Win32 status from
// ProcessTrace (ERROR_SUCCESS or ERROR_CANCELLED on a clean stop).
unsigned long cfgms_run(const unsigned short *sessionNameW);

// cfgms_stop closes the trace so ProcessTrace returns. Safe to call once.
void cfgms_stop(void);

// cfgms_reset clears all whole-run C state (ring indices, counters, provider
// registry, decode sample) so a process may run more than one consume window.
// Call before registering providers for a fresh run.
void cfgms_reset(void);

// cfgms_drain pops up to max events from the ring into out; returns the count.
int cfgms_drain(CfgmsEvent *out, int max);

// cfgms_test_enqueue pushes one synthetic event through the exact producer path
// the callback uses (ring write + total_seen / dropped_ring accounting), so the
// SPSC ring + drain can be unit-tested without ETW privilege. Test-only.
void cfgms_test_enqueue(unsigned int pid, unsigned short provider_idx, unsigned short event_id);

// Counters (monotonic, whole-run):
unsigned long long cfgms_total_seen(void);   // events the callback observed
unsigned long long cfgms_dropped_ring(void); // events dropped because the ring was full

// cfgms_decode_sample returns a malloc'd, NUL-terminated UTF-8 string: one line
// per TDH-decoded sample event, "provider_idx|event_id|Name=Value;Name=Value;...".
// Proof that we extract structured named fields (not just a count). Free with
// cfgms_free. Returns NULL if nothing was decoded.
char *cfgms_decode_sample(void);
void  cfgms_free(char *p);

#endif // CFGMS_DEX_CONSUME_H
