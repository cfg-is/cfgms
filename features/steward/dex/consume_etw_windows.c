// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows && dexconsume && !dexrust

// consume_etw_windows.c — non-reentrant C-callback ETW consumer (#2571).
// See consume_etw_windows.h for the architecture rationale.

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "consume_etw_windows.h"

// mingw-w64's tdh.h declares the TDH functions and structs but not the
// _TDH_IN_TYPE enum. These are stable, documented Windows values — define the
// ones we decode, guarded so a future mingw that adds them does not conflict.
#ifndef TDH_INTYPE_UNICODESTRING
#define TDH_INTYPE_UNICODESTRING 1
#define TDH_INTYPE_ANSISTRING    2
#define TDH_INTYPE_INT8          3
#define TDH_INTYPE_UINT8         4
#define TDH_INTYPE_INT16         5
#define TDH_INTYPE_UINT16        6
#define TDH_INTYPE_INT32         7
#define TDH_INTYPE_UINT32        8
#define TDH_INTYPE_INT64         9
#define TDH_INTYPE_UINT64        10
#define TDH_INTYPE_POINTER       16
#define TDH_INTYPE_HEXINT32      20
#define TDH_INTYPE_HEXINT64      21
#endif

// ─── SPSC ring buffer ────────────────────────────────────────────────────────
// One producer (the ProcessTrace callback thread) and one consumer (the Go drain
// goroutine). Power-of-two capacity; head published with release, tail with
// release, cross-reads with acquire.

#define RING_CAP   (1u << 16)   // 65536 slots
#define RING_MASK  (RING_CAP - 1u)

static CfgmsEvent   g_ring[RING_CAP];
static volatile unsigned int g_head = 0; // producer writes
static volatile unsigned int g_tail = 0; // consumer writes

static volatile long long g_total_seen   = 0;
static volatile long long g_dropped_ring = 0;

// ─── provider registry (for the callback's GUID -> idx stamp) ────────────────

#define MAX_PROVIDERS 16
typedef struct {
    unsigned char guid[16];
    int           idx;
    int           decode_target;
} ProviderEntry;
static ProviderEntry g_providers[MAX_PROVIDERS];
static int           g_provider_count = 0;

void cfgms_register_provider(const unsigned char *guid16, int idx, int is_decode_target) {
    if (g_provider_count >= MAX_PROVIDERS) return;
    memcpy(g_providers[g_provider_count].guid, guid16, 16);
    g_providers[g_provider_count].idx = idx;
    g_providers[g_provider_count].decode_target = is_decode_target;
    g_provider_count++;
}

static int provider_lookup(const GUID *g, int *decode_target) {
    for (int i = 0; i < g_provider_count; i++) {
        if (memcmp(&g_providers[i].guid[0], g, 16) == 0) {
            if (decode_target) *decode_target = g_providers[i].decode_target;
            return g_providers[i].idx;
        }
    }
    if (decode_target) *decode_target = 0;
    return 0xFFFF;
}

// ─── bounded TDH decode sample (Part 2 proof) ────────────────────────────────
// The callback TDH-decodes only the first DECODE_CAP target-provider events into
// a text buffer, so the hot path stays header-only. Read from Go after the run
// (single-threaded producer, no concurrent reader during the run).

#define DECODE_CAP      64
#define DECODE_BUF_SIZE (64 * 1024)
static char g_decode_buf[DECODE_BUF_SIZE];
static int  g_decode_len   = 0;
static int  g_decode_count = 0;

static void decode_appendf(const char *fmt, ...) {
    if (g_decode_len >= DECODE_BUF_SIZE - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(g_decode_buf + g_decode_len, DECODE_BUF_SIZE - g_decode_len, fmt, ap);
    va_end(ap);
    if (n > 0) g_decode_len += n;
    if (g_decode_len > DECODE_BUF_SIZE - 1) g_decode_len = DECODE_BUF_SIZE - 1;
}

// tdh_decode_one enumerates the top-level properties of one event and appends
// "Name=Value;" pairs for the common scalar/string in-types. Best-effort: an
// unrecognised type is skipped. Never allocates unboundedly; caps per-event work.
static void tdh_decode_one(PEVENT_RECORD ev, int provider_idx) {
    DWORD infoSize = 0;
    ULONG st = TdhGetEventInformation(ev, 0, NULL, NULL, &infoSize);
    if (st != ERROR_INSUFFICIENT_BUFFER) return;
    PTRACE_EVENT_INFO info = (PTRACE_EVENT_INFO)malloc(infoSize);
    if (!info) return;
    st = TdhGetEventInformation(ev, 0, NULL, info, &infoSize);
    if (st != ERROR_SUCCESS) { free(info); return; }

    decode_appendf("%d|%u|", provider_idx, (unsigned)ev->EventHeader.EventDescriptor.Id);

    int emitted = 0;
    ULONG count = info->TopLevelPropertyCount;
    if (count > 12) count = 12; // bound per-event work
    for (ULONG i = 0; i < count; i++) {
        EVENT_PROPERTY_INFO *pi = &info->EventPropertyInfoArray[i];
        // Skip structs and array-typed properties for the sample (scalars/strings only).
        if (pi->Flags & (PropertyStruct | PropertyParamCount)) continue;

        const WCHAR *nameW = (const WCHAR *)((PBYTE)info + pi->NameOffset);
        char nameA[128];
        int nn = WideCharToMultiByte(CP_UTF8, 0, nameW, -1, nameA, sizeof(nameA), NULL, NULL);
        if (nn <= 0) continue;

        PROPERTY_DATA_DESCRIPTOR pdd;
        pdd.PropertyName = (ULONGLONG)(ULONG_PTR)nameW;
        pdd.ArrayIndex   = 0;
        pdd.Reserved     = 0;

        DWORD propSize = 0;
        if (TdhGetPropertySize(ev, 0, NULL, 1, &pdd, &propSize) != ERROR_SUCCESS) continue;
        if (propSize == 0 || propSize > 512) continue;
        BYTE buf[512];
        if (TdhGetProperty(ev, 0, NULL, 1, &pdd, propSize, buf) != ERROR_SUCCESS) continue;

        USHORT inType = pi->nonStructType.InType;
        switch (inType) {
            case TDH_INTYPE_UINT8:  decode_appendf("%s=%u;", nameA, (unsigned)*(UINT8 *)buf); emitted++; break;
            case TDH_INTYPE_INT8:   decode_appendf("%s=%d;", nameA, (int)*(INT8 *)buf); emitted++; break;
            case TDH_INTYPE_UINT16: decode_appendf("%s=%u;", nameA, (unsigned)*(UINT16 *)buf); emitted++; break;
            case TDH_INTYPE_INT16:  decode_appendf("%s=%d;", nameA, (int)*(INT16 *)buf); emitted++; break;
            case TDH_INTYPE_UINT32:
            case TDH_INTYPE_HEXINT32: decode_appendf("%s=%lu;", nameA, (unsigned long)*(UINT32 *)buf); emitted++; break;
            case TDH_INTYPE_INT32:  decode_appendf("%s=%ld;", nameA, (long)*(INT32 *)buf); emitted++; break;
            case TDH_INTYPE_UINT64:
            case TDH_INTYPE_HEXINT64:
            case TDH_INTYPE_POINTER: decode_appendf("%s=%llu;", nameA, (unsigned long long)*(UINT64 *)buf); emitted++; break;
            case TDH_INTYPE_INT64:  decode_appendf("%s=%lld;", nameA, (long long)*(INT64 *)buf); emitted++; break;
            case TDH_INTYPE_UNICODESTRING: {
                // Bound the wide-char scan to the property's own byte length: TDH does
                // NOT guarantee a terminating NUL within propSize, so passing -1 would
                // let WideCharToMultiByte read past buf[512]. Convert exactly the
                // wchars the property holds, then NUL-terminate the output ourselves.
                char sval[256];
                int wch = (int)(propSize / sizeof(WCHAR));
                int w = WideCharToMultiByte(CP_UTF8, 0, (WCHAR *)buf, wch, sval, (int)sizeof(sval) - 1, NULL, NULL);
                if (w > 0) {
                    sval[w] = '\0';
                    decode_appendf("%s=%s;", nameA, sval); emitted++;
                }
                break;
            }
            case TDH_INTYPE_ANSISTRING:
                decode_appendf("%s=%.200s;", nameA, (char *)buf); emitted++;
                break;
            default:
                break; // unrecognised scalar type — skip for the sample
        }
        if (emitted >= 6) break; // enough named fields to prove decode
    }
    decode_appendf("\n");
    free(info);
}

// ─── the callback (pure C, never re-enters Go) ───────────────────────────────

// ring_push is the single producer-side enqueue: it counts the event and writes
// it to the ring (or increments dropped_ring when full). Shared by the ETW
// callback and the test hook so both exercise the identical SPSC write path.
static void ring_push(uint64_t timestamp, uint32_t pid, uint32_t tid,
                      uint16_t provider_idx, uint16_t event_id, uint8_t opcode) {
    __atomic_add_fetch(&g_total_seen, 1, __ATOMIC_RELAXED);

    unsigned int head = __atomic_load_n(&g_head, __ATOMIC_RELAXED);
    unsigned int tail = __atomic_load_n(&g_tail, __ATOMIC_ACQUIRE);
    if ((head - tail) >= RING_CAP) {
        __atomic_add_fetch(&g_dropped_ring, 1, __ATOMIC_RELAXED);
        return;
    }
    CfgmsEvent *slot = &g_ring[head & RING_MASK];
    slot->timestamp    = timestamp;
    slot->pid          = pid;
    slot->tid          = tid;
    slot->provider_idx = provider_idx;
    slot->event_id     = event_id;
    slot->opcode       = opcode;
    __atomic_store_n(&g_head, head + 1, __ATOMIC_RELEASE);
}

static void WINAPI cfgms_event_cb(PEVENT_RECORD ev) {
    int decode_target = 0;
    int pidx = provider_lookup(&ev->EventHeader.ProviderId, &decode_target);

    ring_push((uint64_t)ev->EventHeader.TimeStamp.QuadPart,
              ev->EventHeader.ProcessId, ev->EventHeader.ThreadId,
              (uint16_t)pidx, ev->EventHeader.EventDescriptor.Id,
              ev->EventHeader.EventDescriptor.Opcode);

    if (decode_target && g_decode_count < DECODE_CAP) {
        g_decode_count++;
        tdh_decode_one(ev, pidx);
    }
}

void cfgms_test_enqueue(unsigned int pid, unsigned short provider_idx, unsigned short event_id) {
    ring_push(0, pid, 0, provider_idx, event_id, 0);
}

void cfgms_reset(void) {
    __atomic_store_n(&g_head, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_tail, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_total_seen, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_dropped_ring, 0, __ATOMIC_RELAXED);
    g_provider_count = 0;
    g_decode_len = 0;
    g_decode_count = 0;
}

// ─── run / stop ──────────────────────────────────────────────────────────────

static TRACEHANDLE g_trace = (TRACEHANDLE)INVALID_HANDLE_VALUE;

unsigned long cfgms_run(const unsigned short *sessionNameW) {
    EVENT_TRACE_LOGFILEW log;
    ZeroMemory(&log, sizeof(log));
    log.LoggerName          = (LPWSTR)sessionNameW;
    log.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = cfgms_event_cb;

    TRACEHANDLE h = OpenTraceW(&log);
    if (h == (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        return GetLastError();
    }
    g_trace = h;

    ULONG st = ProcessTrace(&h, 1, NULL, NULL);
    return st;
}

void cfgms_stop(void) {
    if (g_trace != (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        CloseTrace(g_trace);
        g_trace = (TRACEHANDLE)INVALID_HANDLE_VALUE;
    }
}

// ─── drain / counters / decode sample ────────────────────────────────────────

int cfgms_drain(CfgmsEvent *out, int max) {
    unsigned int tail = __atomic_load_n(&g_tail, __ATOMIC_RELAXED);
    unsigned int head = __atomic_load_n(&g_head, __ATOMIC_ACQUIRE);
    int n = 0;
    while (tail != head && n < max) {
        out[n] = g_ring[tail & RING_MASK];
        tail++;
        n++;
    }
    __atomic_store_n(&g_tail, tail, __ATOMIC_RELEASE);
    return n;
}

unsigned long long cfgms_total_seen(void)   { return (unsigned long long)__atomic_load_n(&g_total_seen, __ATOMIC_RELAXED); }
unsigned long long cfgms_dropped_ring(void) { return (unsigned long long)__atomic_load_n(&g_dropped_ring, __ATOMIC_RELAXED); }

char *cfgms_decode_sample(void) {
    if (g_decode_len == 0) return NULL;
    char *out = (char *)malloc(g_decode_len + 1);
    if (!out) return NULL;
    memcpy(out, g_decode_buf, g_decode_len);
    out[g_decode_len] = '\0';
    return out;
}

void cfgms_free(char *p) { free(p); }
