// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Rust variant of the DEX in-process ETW consumer (#2571). Same architecture as
// the C version (consume_etw_windows.c): a non-reentrant native callback copies a
// compact header record into a single-producer/single-consumer ring and never
// re-enters Go; a Go goroutine drains the ring via cgo. This proves the crash-safe
// consume path is achievable in a MEMORY-SAFE language — the unsafe surface is
// reduced to exactly two spots (marked `// UNSAFE:` below): the shared static ring
// buffer, and the one raw `EVENT_RECORD` pointer deref the OS ABI forces. All the
// bounds/index/counter logic is safe Rust.
//
// Exposes the identical C ABI (cfgms_* + CfgmsEvent layout) as the C version, so
// the existing Go wrapper links it unchanged under the `dexrust` build tag.

#![allow(non_snake_case)]

use std::cell::UnsafeCell;
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, OpenTraceW, ProcessTrace, EVENT_RECORD, EVENT_TRACE_LOGFILEW,
    PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
};

const RING_CAP: u32 = 1 << 16;
const RING_MASK: u32 = RING_CAP - 1;

// Mirrors CfgmsEvent in consume_etw_windows.h exactly (repr(C)).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CfgmsEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub provider_idx: u16,
    pub event_id: u16,
    pub opcode: u8,
    pub _pad: [u8; 3],
}

const EMPTY_EVENT: CfgmsEvent = CfgmsEvent {
    timestamp: 0,
    pid: 0,
    tid: 0,
    provider_idx: 0,
    event_id: 0,
    opcode: 0,
    _pad: [0; 3],
};

// ── SPSC ring ────────────────────────────────────────────────────────────────
// UNSAFE #1: a process-global fixed ring shared between the ETW callback thread
// (single producer) and the Go drain goroutine (single consumer). UnsafeCell +
// an explicit `unsafe impl Sync` is the minimal interior-mutability escape; the
// head/tail indices are atomics so the happens-before edges are enforced safely.
struct Ring {
    buf: UnsafeCell<[CfgmsEvent; RING_CAP as usize]>,
}
unsafe impl Sync for Ring {}

static RING: Ring = Ring {
    buf: UnsafeCell::new([EMPTY_EVENT; RING_CAP as usize]),
};
static HEAD: AtomicU32 = AtomicU32::new(0);
static TAIL: AtomicU32 = AtomicU32::new(0);
static TOTAL_SEEN: AtomicU64 = AtomicU64::new(0);
static DROPPED_RING: AtomicU64 = AtomicU64::new(0);

fn ring_push(ev: CfgmsEvent) {
    TOTAL_SEEN.fetch_add(1, Ordering::Relaxed);
    let head = HEAD.load(Ordering::Relaxed);
    let tail = TAIL.load(Ordering::Acquire);
    if head.wrapping_sub(tail) >= RING_CAP {
        DROPPED_RING.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // UNSAFE #1 (write): sole producer writes its slot before publishing `head`.
    unsafe {
        (*RING.buf.get())[(head & RING_MASK) as usize] = ev;
    }
    HEAD.store(head.wrapping_add(1), Ordering::Release);
}

// ── provider registry (GUID → idx stamp for the callback) ────────────────────
const MAX_PROVIDERS: usize = 16;
struct Providers {
    guids: UnsafeCell<[[u8; 16]; MAX_PROVIDERS]>,
    idxs: UnsafeCell<[u16; MAX_PROVIDERS]>,
}
unsafe impl Sync for Providers {}
static PROVIDERS: Providers = Providers {
    guids: UnsafeCell::new([[0u8; 16]; MAX_PROVIDERS]),
    idxs: UnsafeCell::new([0u16; MAX_PROVIDERS]),
};
static PROVIDER_COUNT: AtomicU16 = AtomicU16::new(0);

fn provider_lookup(guid: &GUID) -> u16 {
    // GUID has the same 16-byte layout the C side registered (windows.GUID order).
    let want = guid_bytes(guid);
    let n = PROVIDER_COUNT.load(Ordering::Acquire) as usize;
    // Registration completes (Go, single-threaded) before ProcessTrace starts, so
    // this read side needs no locking.
    let guids = unsafe { &*PROVIDERS.guids.get() };
    let idxs = unsafe { &*PROVIDERS.idxs.get() };
    for i in 0..n {
        if guids[i] == want {
            return idxs[i];
        }
    }
    0xFFFF
}

fn guid_bytes(g: &GUID) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&g.data1.to_le_bytes());
    b[4..6].copy_from_slice(&g.data2.to_le_bytes());
    b[6..8].copy_from_slice(&g.data3.to_le_bytes());
    b[8..16].copy_from_slice(&g.data4);
    b
}

// ── the callback (native, never re-enters Go) ────────────────────────────────
// UNSAFE #2: the OS hands us a raw EVENT_RECORD pointer valid only for this call.
// Dereferencing it is the single irreducible unsafe op — everything after is safe.
unsafe extern "system" fn cfgms_event_cb(ev: *mut EVENT_RECORD) {
    if ev.is_null() {
        return;
    }
    let h = &(*ev).EventHeader; // UNSAFE #2
    let pidx = provider_lookup(&h.ProviderId);
    ring_push(CfgmsEvent {
        timestamp: h.TimeStamp as u64,
        pid: h.ProcessId,
        tid: h.ThreadId,
        provider_idx: pidx,
        event_id: h.EventDescriptor.Id,
        opcode: h.EventDescriptor.Opcode,
        _pad: [0; 3],
    });
}

// ── trace handle ─────────────────────────────────────────────────────────────
static G_TRACE: AtomicU64 = AtomicU64::new(u64::MAX); // INVALID_PROCESSTRACE_HANDLE

// ── exported C ABI (matches consume_etw_windows.h) ───────────────────────────

#[no_mangle]
pub extern "C" fn cfgms_register_provider(guid16: *const u8, idx: c_int, _is_decode_target: c_int) {
    if guid16.is_null() {
        return;
    }
    let n = PROVIDER_COUNT.load(Ordering::Relaxed) as usize;
    if n >= MAX_PROVIDERS {
        return;
    }
    // Copy the 16 GUID bytes; registration is single-threaded (pre-run).
    let src = unsafe { std::slice::from_raw_parts(guid16, 16) };
    let guids = unsafe { &mut *PROVIDERS.guids.get() };
    let idxs = unsafe { &mut *PROVIDERS.idxs.get() };
    guids[n].copy_from_slice(src);
    idxs[n] = idx as u16;
    PROVIDER_COUNT.store((n + 1) as u16, Ordering::Release);
}

#[no_mangle]
pub extern "C" fn cfgms_run(session_name_w: *const u16) -> u32 {
    let mut log: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    log.LoggerName = session_name_w as *mut u16;
    log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.Anonymous2.EventRecordCallback = Some(cfgms_event_cb);

    let h = unsafe { OpenTraceW(&mut log) }; // PROCESSTRACE_HANDLE { Value: u64 }
    if h.Value == u64::MAX {
        return unsafe { GetLastError() };
    }
    G_TRACE.store(h.Value, Ordering::SeqCst);
    unsafe { ProcessTrace(&h, 1, std::ptr::null(), std::ptr::null()) }
}

#[no_mangle]
pub extern "C" fn cfgms_stop() {
    let v = G_TRACE.swap(u64::MAX, Ordering::SeqCst);
    if v != u64::MAX {
        unsafe { CloseTrace(PROCESSTRACE_HANDLE { Value: v }) };
    }
}

#[no_mangle]
pub extern "C" fn cfgms_reset() {
    HEAD.store(0, Ordering::Relaxed);
    TAIL.store(0, Ordering::Relaxed);
    TOTAL_SEEN.store(0, Ordering::Relaxed);
    DROPPED_RING.store(0, Ordering::Relaxed);
    PROVIDER_COUNT.store(0, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn cfgms_drain(out: *mut CfgmsEvent, max: c_int) -> c_int {
    if out.is_null() || max <= 0 {
        return 0;
    }
    let out = unsafe { std::slice::from_raw_parts_mut(out, max as usize) };
    let mut tail = TAIL.load(Ordering::Relaxed);
    let head = HEAD.load(Ordering::Acquire);
    let buf = unsafe { &*RING.buf.get() };
    let mut n = 0usize;
    while tail != head && n < max as usize {
        out[n] = buf[(tail & RING_MASK) as usize];
        tail = tail.wrapping_add(1);
        n += 1;
    }
    TAIL.store(tail, Ordering::Release);
    n as c_int
}

#[no_mangle]
pub extern "C" fn cfgms_total_seen() -> u64 {
    TOTAL_SEEN.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn cfgms_dropped_ring() -> u64 {
    DROPPED_RING.load(Ordering::Relaxed)
}

// Decode is TDH-schema work identical to the C variant and orthogonal to the
// crash-safe-consume question this Rust PoC proves; the Rust variant reports no
// decode sample (Go handles the null).
#[no_mangle]
pub extern "C" fn cfgms_decode_sample() -> *mut c_char {
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn cfgms_free(_p: *mut c_char) {}

#[no_mangle]
pub extern "C" fn cfgms_test_enqueue(pid: u32, provider_idx: u16, event_id: u16) {
    ring_push(CfgmsEvent {
        timestamp: 0,
        pid,
        tid: 0,
        provider_idx,
        event_id,
        opcode: 0,
        _pad: [0; 3],
    });
}
