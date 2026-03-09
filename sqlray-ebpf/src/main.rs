#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_buf},
    macros::{map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::TracePointContext,
};

const MAX_SQL_LEN: usize = 512;
const MAX_MESSAGES: usize = 8;
const PG_MSG_HEADER: u32 = 5; // 1 byte type + 4 bytes length

/// Byte offset of `ubuf` in sys_enter_recvfrom tracepoint format.
const RECVFROM_ENTER_BUF_OFF: usize = 24;
/// Byte offset of `ret` in sys_exit_recvfrom tracepoint format.
const RECVFROM_EXIT_RET_OFF: usize = 16;

#[repr(u32)]
#[derive(Copy, Clone)]
enum EventType {
    Query = 0,
    Parse = 1,
    Bind = 2,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SqlEvent {
    pid: u32,
    len: u32,
    event_type: u32,
    buf: [u8; MAX_SQL_LEN],
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

#[map]
static SQL_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static ACTIVE_READS: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

/// Index 0: PID filter enabled (0 = trace all, 1 = filter by TARGET_PIDS).
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

/// Set of PIDs to trace. Only consulted when CONFIG[0] != 0.
#[map]
static TARGET_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

const CFG_FILTER_PID: u32 = 0;

#[tracepoint(category = "syscalls", name = "sys_enter_recvfrom")]
pub fn trace_enter_recvfrom(ctx: TracePointContext) -> u32 {
    try_enter_recvfrom(&ctx).unwrap_or(0)
}

fn try_enter_recvfrom(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if let Some(&enabled) = CONFIG.get(CFG_FILTER_PID) {
        let is_targeted = unsafe { TARGET_PIDS.get(&pid) }.is_some();
        if enabled != 0 && !is_targeted {
            return Ok(0);
        }
    }

    let buf_addr: u64 = unsafe { ctx.read_at(RECVFROM_ENTER_BUF_OFF)? };
    ACTIVE_READS.insert(&pid_tgid, &buf_addr, 0)?;
    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_exit_recvfrom")]
pub fn trace_exit_recvfrom(ctx: TracePointContext) -> u32 {
    try_exit_recvfrom(&ctx).unwrap_or(0)
}

fn try_exit_recvfrom(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let buf_addr = match unsafe { ACTIVE_READS.get(&pid_tgid) } {
        Some(addr) => *addr,
        None => return Ok(0),
    };
    let _ = ACTIVE_READS.remove(&pid_tgid);

    let ret: i64 = unsafe { ctx.read_at(RECVFROM_EXIT_RET_OFF)? };
    if ret < PG_MSG_HEADER as i64 {
        return Ok(0);
    }

    let pid = (pid_tgid >> 32) as u32;
    handle_pg_buffer(pid, buf_addr as *const u8, ret as u32)
}

#[inline(always)]
fn handle_pg_buffer(pid: u32, buf_ptr: *const u8, count: u32) -> Result<u32, i64> {
    let mut off: u32 = 0;

    for _ in 0..MAX_MESSAGES {
        if off + PG_MSG_HEADER > count {
            break;
        }

        // Single read for the 5-byte message header (type + length).
        let mut hdr = [0u8; 5];
        unsafe { bpf_probe_read_user_buf(buf_ptr.add(off as usize), &mut hdr)? };
        let msg_type = hdr[0];
        let msg_len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);

        let msg_total = 1u32.saturating_add(msg_len);
        if msg_total < PG_MSG_HEADER {
            break;
        }
        if off + msg_total > count {
            break;
        }

        match msg_type {
            b'Q' => emit_event(pid, buf_ptr, off, msg_total, EventType::Query)?,
            b'P' => emit_event(pid, buf_ptr, off, msg_total, EventType::Parse)?,
            b'B' => emit_event(pid, buf_ptr, off, msg_total, EventType::Bind)?,
            _ => {}
        }

        off += msg_total;
    }

    Ok(0)
}

#[inline(always)]
fn emit_event(
    pid: u32,
    buf_ptr: *const u8,
    msg_off: u32,
    msg_total: u32,
    event_type: EventType,
) -> Result<(), i64> {
    if msg_total <= PG_MSG_HEADER {
        return Ok(());
    }

    let data_len = msg_total - PG_MSG_HEADER;
    let capped = core::cmp::min(data_len as usize, MAX_SQL_LEN - 1);
    // Mask to satisfy the BPF verifier's bounds check (MAX_SQL_LEN is a power of two).
    let read_len = capped & (MAX_SQL_LEN - 1);

    if let Some(mut entry) = SQL_EVENTS.reserve::<SqlEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.pid = pid;
        event.event_type = event_type as u32;
        event.len = read_len as u32;

        let src = unsafe { buf_ptr.add((msg_off + PG_MSG_HEADER) as usize) };
        if read_len > 0 {
            if unsafe { bpf_probe_read_user_buf(src, &mut event.buf[..read_len]) }.is_err() {
                entry.discard(0);
                return Ok(());
            }
        }
        entry.submit(0);
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
