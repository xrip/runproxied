// agyproxy: SOCKS5 redirector injected as dbghelp.dll next to agy.exe.
// Routes every TCP connect and every UDP datagram of the host process
// through a SOCKS5 (socks5h) proxy. x86_64-windows-gnu, Zig.
const std = @import("std");

const SOCKET = usize;
const INVALID_SOCKET: SOCKET = ~@as(SOCKET, 0);
const SOCKET_ERROR: c_int = -1;
const INVALID_HANDLE: usize = ~@as(usize, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;
const SOCK_STREAM: c_int = 1;
const SOCK_DGRAM: c_int = 2;
const SOL_SOCKET: c_int = 0xffff;
const WSAEWOULDBLOCK: c_int = 10035;
const SO_TYPE: c_int = 0x1008;
const SO_RCVTIMEO: c_int = 0x1006;
const SO_SNDTIMEO: c_int = 0x1005;

const POLLRDNORM: i16 = 0x0100;
const TH32CS_SNAPMODULE: u32 = 0x00000008;

const OVERLAPPED = extern struct {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    h_event: ?*anyopaque,
};
const WSABUF = extern struct { len: u32, buf: ?[*]u8 };
const WSAPOLLFD = extern struct { fd: SOCKET, events: i16, revents: i16 };

const sockaddr = extern struct { family: u16, data: [14]u8 };
const SockAddrStore = extern struct { data: [128]u8 align(8) };

const addrinfo = extern struct {
    flags: c_int,
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    addrlen: usize,
    canonname: ?[*:0]u8,
    addr: ?*sockaddr,
    next: ?*addrinfo,
};

const MODULEENTRY32W = extern struct {
    dwSize: u32,
    th32ModuleID: u32,
    th32ProcessID: u32,
    GlblcntUsage: u32,
    ProccntUsage: u32,
    modBaseAddr: ?*anyopaque,
    modBaseSize: u32,
    hModule: ?*anyopaque,
    szModule: [256]u16,
    szExePath: [260]u16,
};

const IMAGE_IMPORT_DESCRIPTOR = extern struct {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
};

// ---------------------------------------------------------------------------
// imports
// ---------------------------------------------------------------------------
extern "kernel32" fn GetModuleHandleA(name: ?[*:0]const u8) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetModuleFileNameA(h: ?*anyopaque, buf: [*]u8, n: u32) callconv(.winapi) u32;
extern "kernel32" fn GetModuleHandleExW(flags: u32, addr: ?*const anyopaque, out: *?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn LoadLibraryA(name: [*:0]const u8) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn VirtualProtect(addr: ?*anyopaque, size: usize, newp: u32, old: *u32) callconv(.winapi) i32;
extern "kernel32" fn GetProcessHeap() callconv(.winapi) ?*anyopaque;
extern "kernel32" fn HeapAlloc(h: ?*anyopaque, flags: u32, size: usize) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn HeapFree(h: ?*anyopaque, flags: u32, p: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn CreateThread(sec: ?*anyopaque, stack: usize, start: *const fn (?*anyopaque) callconv(.winapi) u32, arg: ?*anyopaque, flags: u32, id: ?*u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn CloseHandle(h: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn CreateToolhelp32Snapshot(flags: u32, pid: u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn Module32FirstW(snap: ?*anyopaque, me: *MODULEENTRY32W) callconv(.winapi) i32;
extern "kernel32" fn Module32NextW(snap: ?*anyopaque, me: *MODULEENTRY32W) callconv(.winapi) i32;
extern "kernel32" fn GetTempPathA(n: u32, buf: [*]u8) callconv(.winapi) u32;
extern "kernel32" fn GetEnvironmentVariableA(name: [*:0]const u8, buf: [*]u8, n: u32) callconv(.winapi) u32;
extern "kernel32" fn CreateFileA(name: [*:0]const u8, access: u32, share: u32, sec: ?*anyopaque, disp: u32, flags: u32, tmpl: ?*anyopaque) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn WriteFile(h: ?*anyopaque, buf: [*]const u8, n: u32, written: *u32, ov: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn GetTickCount64() callconv(.winapi) u64;
extern "kernel32" fn InitializeSRWLock(l: *usize) callconv(.winapi) void;
extern "kernel32" fn AcquireSRWLockExclusive(l: *usize) callconv(.winapi) void;
extern "kernel32" fn ReleaseSRWLockExclusive(l: *usize) callconv(.winapi) void;
extern "kernel32" fn PostQueuedCompletionStatus(port: ?*anyopaque, bytes: u32, key: usize, ov: *OVERLAPPED) callconv(.winapi) i32;
extern "kernel32" fn DisableThreadLibraryCalls(h: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn VirtualAlloc(addr: ?*anyopaque, size: usize, typ: u32, prot: u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn FlushInstructionCache(h: ?*anyopaque, addr: ?*const anyopaque, size: usize) callconv(.winapi) i32;
extern "kernel32" fn GetCurrentThreadId() callconv(.winapi) u32;
extern "kernel32" fn OpenThread(access: u32, inherit: i32, id: u32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn SuspendThread(h: ?*anyopaque) callconv(.winapi) u32;
extern "kernel32" fn ResumeThread(h: ?*anyopaque) callconv(.winapi) u32;
extern "kernel32" fn Thread32First(snap: ?*anyopaque, te: *THREADENTRY32) callconv(.winapi) i32;
extern "kernel32" fn Thread32Next(snap: ?*anyopaque, te: *THREADENTRY32) callconv(.winapi) i32;

const TH32CS_SNAPTHREAD: u32 = 0x4;
const THREADENTRY32 = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ThreadID: u32,
    th32OwnerProcessID: u32,
    tpBasePri: i32,
    tpDeltaPri: i32,
    dwFlags: u32,
};

extern fn hde64_disasm(code: [*]const u8, hs: [*]u8) u32;

const ANSI_STRING = extern struct { Length: u16, MaximumLength: u16, Buffer: ?[*]u8 };
extern "ntdll" fn LdrGetProcedureAddress(h: ?*anyopaque, name: ?*ANSI_STRING, ordinal: usize, out: *?*anyopaque) callconv(.winapi) i32;

extern "ws2_32" fn socket(af: c_int, t: c_int, p: c_int) callconv(.winapi) SOCKET;
extern "ws2_32" fn bind(s: SOCKET, a: *const sockaddr, l: c_int) callconv(.winapi) c_int;
extern "ws2_32" fn listen(s: SOCKET, b: c_int) callconv(.winapi) c_int;
extern "ws2_32" fn accept(s: SOCKET, a: *sockaddr, l: *c_int) callconv(.winapi) SOCKET;
extern "ws2_32" fn getsockname(s: SOCKET, a: *sockaddr, l: *c_int) callconv(.winapi) c_int;
extern "ws2_32" fn getsockopt(s: SOCKET, lvl: c_int, opt: c_int, val: [*]u8, len: *c_int) callconv(.winapi) c_int;
extern "ws2_32" fn setsockopt(s: SOCKET, lvl: c_int, opt: c_int, val: [*]const u8, len: c_int) callconv(.winapi) c_int;
extern "ws2_32" fn WSAPoll(fds: [*]WSAPOLLFD, n: u32, timeout: c_int) callconv(.winapi) c_int;
extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
extern "ws2_32" fn WSASetLastError(e: c_int) callconv(.winapi) void;

// ---------------------------------------------------------------------------
// intercepted function pointer types
// ---------------------------------------------------------------------------
const FnConnect = *const fn (SOCKET, ?*const sockaddr, c_int) callconv(.winapi) c_int;
const FnWSAConnect = *const fn (SOCKET, ?*const sockaddr, c_int, ?*anyopaque, ?*anyopaque, ?*anyopaque, ?*anyopaque) callconv(.winapi) c_int;
const FnSendTo = *const fn (SOCKET, ?[*]const u8, c_int, c_int, ?*const sockaddr, c_int) callconv(.winapi) c_int;
const FnWSASendTo = *const fn (SOCKET, ?[*]WSABUF, u32, ?*u32, u32, ?*const sockaddr, c_int, ?*OVERLAPPED, ?*anyopaque) callconv(.winapi) c_int;
const FnRecvFrom = *const fn (SOCKET, ?[*]u8, c_int, c_int, ?*sockaddr, ?*c_int) callconv(.winapi) c_int;
const FnWSARecvFrom = *const fn (SOCKET, ?[*]WSABUF, u32, ?*u32, ?*u32, ?*sockaddr, ?*c_int, ?*OVERLAPPED, ?*anyopaque) callconv(.winapi) c_int;
const FnSend = *const fn (SOCKET, ?[*]const u8, c_int, c_int) callconv(.winapi) c_int;
const FnWSASend = *const fn (SOCKET, ?[*]WSABUF, u32, ?*u32, u32, ?*OVERLAPPED, ?*anyopaque) callconv(.winapi) c_int;
const FnRecv = *const fn (SOCKET, ?[*]u8, c_int, c_int) callconv(.winapi) c_int;
const FnWSARecv = *const fn (SOCKET, ?[*]WSABUF, u32, ?*u32, ?*u32, ?*OVERLAPPED, ?*anyopaque) callconv(.winapi) c_int;
const FnGetAddrInfo = *const fn (?[*:0]const u8, ?[*:0]const u8, ?*const addrinfo, ?*?*addrinfo) callconv(.winapi) c_int;
const FnFreeAddrInfo = *const fn (?*addrinfo) callconv(.winapi) void;
const FnGetAddrInfoW = *const fn (?[*:0]const u16, ?[*:0]const u16, ?*const addrinfo, ?*?*addrinfo) callconv(.winapi) c_int;
const FnFreeAddrInfoW = *const fn (?*addrinfo) callconv(.winapi) void;
const FnCloseSocket = *const fn (SOCKET) callconv(.winapi) c_int;
const FnGetProc = *const fn (?*anyopaque, [*:0]const u8) callconv(.winapi) ?*anyopaque;
const FnLoadLibA = *const fn ([*:0]const u8) callconv(.winapi) ?*anyopaque;
const FnLoadLibW = *const fn ([*:0]const u16) callconv(.winapi) ?*anyopaque;
const FnLoadLibExA = *const fn ([*:0]const u8, ?*anyopaque, u32) callconv(.winapi) ?*anyopaque;
const FnLoadLibExW = *const fn ([*:0]const u16, ?*anyopaque, u32) callconv(.winapi) ?*anyopaque;
const FnCreateIOCP = *const fn (?*anyopaque, ?*anyopaque, usize, u32) callconv(.winapi) ?*anyopaque;
const FnHostEnt = *const fn (?*anyopaque) callconv(.winapi) ?*anyopaque;
const FnConnectEx = *const fn (SOCKET, ?*const sockaddr, c_int, ?*anyopaque, u32, ?*u32, ?*OVERLAPPED) callconv(.winapi) i32;
var real_connectex: FnConnectEx = &stub_connectex;
const FnWSAIoctl = *const fn (SOCKET, u32, ?*anyopaque, u32, ?*anyopaque, u32, ?*u32, ?*OVERLAPPED, ?*anyopaque) callconv(.winapi) c_int;
var real_wsaioctl: FnWSAIoctl = &stub_wsaioctl;

const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC8000006;
// {25a207b9-ddf3-4660-8ee9-76e58c74063e} in memory (little-endian Data1..3)
const WSAID_CONNECTEX = [16]u8{ 0xb9, 0x07, 0xa2, 0x25, 0xf3, 0xdd, 0x60, 0x46, 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e };
const FnSocket = *const fn (c_int, c_int, c_int) callconv(.winapi) SOCKET;
var real_socket: FnSocket = &stub_socket;

const OVERLAPPED_ENTRY = extern struct { key: usize, ov: ?*OVERLAPPED, internal: usize, bytes: u32, pad: u32 };
const FnGQCS = *const fn (?*anyopaque, *u32, *usize, *?*OVERLAPPED, u32) callconv(.winapi) i32;
const FnGQCSEx = *const fn (?*anyopaque, [*]OVERLAPPED_ENTRY, u32, *u32, u32) callconv(.winapi) i32;

var real_connect: FnConnect = &stub_connect;
var real_wsaconnect: FnWSAConnect = &stub_wsaconnect;
var real_sendto: FnSendTo = &stub_sendto;
var real_wsasendto: FnWSASendTo = &stub_wsasendto;
var real_recvfrom: FnRecvFrom = &stub_recvfrom;
var real_wsarecvfrom: FnWSARecvFrom = &stub_wsarecvfrom;
var real_send: FnSend = &stub_send;
var real_wsasend: FnWSASend = &stub_wsasend;
var real_recv: FnRecv = &stub_recv;
var real_wsarecv: FnWSARecv = &stub_wsarecv;
var real_getaddrinfo: FnGetAddrInfo = &stub_getaddrinfo;
var real_freeaddrinfo: FnFreeAddrInfo = &stub_freeaddrinfo;
var real_getaddrinfow: FnGetAddrInfoW = &stub_getaddrinfow;
var real_freeaddrinfow: FnFreeAddrInfoW = &stub_freeaddrinfow;
var real_closesocket: FnCloseSocket = &stub_closesocket;
var real_getproc: FnGetProc = &stub_getproc;
var real_loadliba: FnLoadLibA = &stub_loadliba;
var real_loadlibw: FnLoadLibW = &stub_loadlibw;
var real_loadlibexa: FnLoadLibExA = &stub_loadlibexa;
var real_loadlibexw: FnLoadLibExW = &stub_loadlibexw;
var real_createiocp: FnCreateIOCP = &stub_createiocp;
var real_gethostbyname: FnHostEnt = &stub_gethostbyname;
var real_gqcs: FnGQCS = &stub_gqcs;
var real_gqcsex: FnGQCSEx = &stub_gqcsex;

fn stub_connect(s: SOCKET, a: ?*const sockaddr, l: c_int) callconv(.winapi) c_int { _ = s; _ = a; _ = l; return SOCKET_ERROR; }
fn stub_wsaconnect(s: SOCKET, a: ?*const sockaddr, l: c_int, b: ?*anyopaque, c: ?*anyopaque, d: ?*anyopaque, e: ?*anyopaque) callconv(.winapi) c_int { _ = s; _ = a; _ = l; _ = b; _ = c; _ = d; _ = e; return SOCKET_ERROR; }
fn stub_sendto(s: SOCKET, b: ?[*]const u8, l: c_int, f: c_int, a: ?*const sockaddr, al: c_int) callconv(.winapi) c_int { _ = s; _ = b; _ = l; _ = f; _ = a; _ = al; return SOCKET_ERROR; }
fn stub_wsasendto(s: SOCKET, b: ?[*]WSABUF, c: u32, n: ?*u32, f: u32, a: ?*const sockaddr, al: c_int, o: ?*OVERLAPPED, cr: ?*anyopaque) callconv(.winapi) c_int { _ = s; _ = b; _ = c; _ = n; _ = f; _ = a; _ = al; _ = o; _ = cr; return SOCKET_ERROR; }
fn stub_recvfrom(s: SOCKET, b: ?[*]u8, l: c_int, f: c_int, a: ?*sockaddr, al: ?*c_int) callconv(.winapi) c_int { _ = s; _ = b; _ = l; _ = f; _ = a; _ = al; return SOCKET_ERROR; }
fn stub_wsarecvfrom(s: SOCKET, b: ?[*]WSABUF, c: u32, n: ?*u32, f: ?*u32, a: ?*sockaddr, al: ?*c_int, o: ?*OVERLAPPED, cr: ?*anyopaque) callconv(.winapi) c_int { _ = s; _ = b; _ = c; _ = n; _ = f; _ = a; _ = al; _ = o; _ = cr; return SOCKET_ERROR; }
fn stub_send(s: SOCKET, b: ?[*]const u8, l: c_int, f: c_int) callconv(.winapi) c_int { _ = s; _ = b; _ = l; _ = f; return SOCKET_ERROR; }
fn stub_wsasend(s: SOCKET, b: ?[*]WSABUF, c: u32, n: ?*u32, f: u32, o: ?*OVERLAPPED, cr: ?*anyopaque) callconv(.winapi) c_int { _ = s; _ = b; _ = c; _ = n; _ = f; _ = o; _ = cr; return SOCKET_ERROR; }
fn stub_recv(s: SOCKET, b: ?[*]u8, l: c_int, f: c_int) callconv(.winapi) c_int { _ = s; _ = b; _ = l; _ = f; return SOCKET_ERROR; }
fn stub_wsarecv(s: SOCKET, b: ?[*]WSABUF, c: u32, n: ?*u32, f: ?*u32, o: ?*OVERLAPPED, cr: ?*anyopaque) callconv(.winapi) c_int { _ = s; _ = b; _ = c; _ = n; _ = f; _ = o; _ = cr; return SOCKET_ERROR; }
fn stub_getaddrinfo(a: ?[*:0]const u8, b: ?[*:0]const u8, c: ?*const addrinfo, d: ?*?*addrinfo) callconv(.winapi) c_int { _ = a; _ = b; _ = c; _ = d; return 2; }
fn stub_freeaddrinfo(a: ?*addrinfo) callconv(.winapi) void { _ = a; }
fn stub_getaddrinfow(a: ?[*:0]const u16, b: ?[*:0]const u16, c: ?*const addrinfo, d: ?*?*addrinfo) callconv(.winapi) c_int { _ = a; _ = b; _ = c; _ = d; return 2; }
fn stub_freeaddrinfow(a: ?*addrinfo) callconv(.winapi) void { _ = a; }
fn stub_closesocket(s: SOCKET) callconv(.winapi) c_int { _ = s; return SOCKET_ERROR; }
fn stub_getproc(h: ?*anyopaque, n: [*:0]const u8) callconv(.winapi) ?*anyopaque { _ = h; _ = n; return null; }
fn stub_loadliba(n: [*:0]const u8) callconv(.winapi) ?*anyopaque { _ = n; return null; }
fn stub_loadlibw(n: [*:0]const u16) callconv(.winapi) ?*anyopaque { _ = n; return null; }
fn stub_loadlibexa(n: [*:0]const u8, f: ?*anyopaque, fl: u32) callconv(.winapi) ?*anyopaque { _ = n; _ = f; _ = fl; return null; }
fn stub_loadlibexw(n: [*:0]const u16, f: ?*anyopaque, fl: u32) callconv(.winapi) ?*anyopaque { _ = n; _ = f; _ = fl; return null; }
fn stub_createiocp(f: ?*anyopaque, e: ?*anyopaque, k: usize, t: u32) callconv(.winapi) ?*anyopaque { _ = f; _ = e; _ = k; _ = t; return null; }
fn stub_gethostbyname(n: ?*anyopaque) callconv(.winapi) ?*anyopaque { _ = n; return null; }
fn stub_socket(a: c_int, t: c_int, p: c_int) callconv(.winapi) SOCKET { _ = a; _ = t; _ = p; return INVALID_SOCKET; }
fn stub_connectex(s: SOCKET, a: ?*const sockaddr, l: c_int, b: ?*anyopaque, bl: u32, bs: ?*u32, o: ?*OVERLAPPED) callconv(.winapi) i32 { _ = s; _ = a; _ = l; _ = b; _ = bl; _ = bs; _ = o; return 0; }
fn stub_wsaioctl(s: SOCKET, c: u32, i: ?*anyopaque, il: u32, o: ?*anyopaque, ol: u32, b: ?*u32, ov: ?*OVERLAPPED, cr: ?*anyopaque) callconv(.winapi) c_int { _ = s; _ = c; _ = i; _ = il; _ = o; _ = ol; _ = b; _ = ov; _ = cr; return SOCKET_ERROR; }
fn stub_gqcs(p: ?*anyopaque, b: *u32, k: *usize, o: *?*OVERLAPPED, ms: u32) callconv(.winapi) i32 { _ = p; _ = b; _ = k; _ = o; _ = ms; return 0; }
fn stub_gqcsex(p: ?*anyopaque, e: [*]OVERLAPPED_ENTRY, m: u32, r: *u32, ms: u32) callconv(.winapi) i32 { _ = p; _ = e; _ = m; _ = r; _ = ms; return 0; }
// ---------------------------------------------------------------------------
// logging
// ---------------------------------------------------------------------------
var log_path: [640]u8 = @splat(0);
var log_path_len: usize = 0;
var log_ready: bool = false;
var log_lock: usize = 0;
var verbose: bool = false;

var log_off: bool = false;

fn logBuildPath() bool {
    // log next to the target exe, named <exe>.runproxied.log, so several
    // proxied programs never fight over one file
    var exepath: [600]u8 = @splat(0);
    const en = GetModuleFileNameA(null, &exepath, 590);
    if (en == 0 or en > 590) return false;
    var dir_end: usize = @intCast(en);
    while (dir_end > 0 and exepath[dir_end - 1] != '\\') dir_end -= 1;
    var stem_end: usize = @intCast(en);
    while (stem_end > dir_end and exepath[stem_end - 1] != '.') stem_end -= 1;
    var stem_len: usize = @as(usize, @intCast(en)) - dir_end; // whole name if no extension
    if (stem_end > dir_end) stem_len = stem_end - 1 - dir_end; // exclude the dot
    const tail = ".runproxied.log";
    const total = dir_end + stem_len + tail.len;
    if (total + 1 > log_path.len) return false;
    @memcpy(log_path[0..dir_end], exepath[0..dir_end]);
    @memcpy(log_path[dir_end .. dir_end + stem_len], exepath[dir_end .. dir_end + stem_len]);
    @memcpy(log_path[dir_end + stem_len .. total], tail);
    log_path[total] = 0;
    // verify the directory is writable; otherwise fall back to %TEMP%
    const probe = CreateFileA(@ptrCast(&log_path), 4, 3, null, 4, 0x80, null);
    if (probe) |f| {
        _ = CloseHandle(f);
        log_path_len = total;
        return true;
    }
    var tmp: [320]u8 = @splat(0);
    const n = GetTempPathA(300, &tmp);
    if (n == 0 or n > 300) return false;
    var pid_s: [16]u8 = @splat(0);
    const ps = std.fmt.bufPrint(&pid_s, "runproxied-{d}.log", .{GetCurrentProcessId()}) catch return false;
    if (n + ps.len + 1 > log_path.len) return false;
    @memcpy(log_path[0..n], tmp[0..n]);
    @memcpy(log_path[n .. n + ps.len], ps);
    log_path[n + ps.len] = 0;
    log_path_len = n + ps.len;
    return true;
}

fn logInit() void {
    if (log_ready) return;
    var qb: [8]u8 = @splat(0);
    const qn = GetEnvironmentVariableA("AGYPROXY_QUIET", &qb, qb.len);
    if (qn >= 1 and (qb[0] == '1' or qb[0] == 'y' or qb[0] == 'Y')) {
        log_off = true;
        log_ready = true;
        return;
    }
    var vb: [8]u8 = @splat(0);
    const vn = GetEnvironmentVariableA("AGYPROXY_VERBOSE", &vb, vb.len);
    verbose = vn >= 1 and vb[0] == '1';
    log_ready = true;
    if (!logBuildPath()) log_off = true;
}

fn logRaw(msg: []const u8) void {
    if (!log_ready or log_off) return;
    AcquireSRWLockExclusive(&log_lock);
    defer ReleaseSRWLockExclusive(&log_lock);
    const f = CreateFileA(@ptrCast(&log_path), 4, 3, null, 4, 0x80, null) orelse return;
    defer _ = CloseHandle(f);
    var written: u32 = 0;
    _ = WriteFile(f, msg.ptr, @intCast(msg.len), &written, null);
    _ = WriteFile(f, "\r\n", 2, &written, null);
}

fn logf(comptime fmt: []const u8, args: anytype) void {
    var buf: [1400]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    logRaw(msg);
}

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------
const DEFAULT_PROXY = ""; // no built-in proxy; configure via AGY_PROXY env (set by the launcher)

var cfg_enabled: bool = true;
var cfg_host: [256]u8 = @splat(0);
var cfg_host_len: usize = 0;
var cfg_port: u16 = 1080;
var cfg_user: [128]u8 = @splat(0);
var cfg_user_len: usize = 0;
var cfg_pass: [128]u8 = @splat(0);
var cfg_pass_len: usize = 0;
var cfg_ready: bool = false;

fn cfgInit() void {
    var raw: [512]u8 = @splat(0);
    var n = GetEnvironmentVariableA("AGY_PROXY", &raw, raw.len);
    if (n == 0 or n >= raw.len) {
        const d = DEFAULT_PROXY;
        @memcpy(raw[0..d.len], d);
        n = d.len;
    }
    var s: []const u8 = raw[0..n];
    logf("config: {s}", .{s});
    if (s.len == 0 or std.mem.eql(u8, s, "none") or std.mem.eql(u8, s, "direct")) {
        cfg_enabled = false;
        cfg_ready = true;
        logRaw("proxying disabled by config");
        return;
    }
    if (std.mem.startsWith(u8, s, "socks5h://")) {
        s = s[10..];
    } else if (std.mem.startsWith(u8, s, "socks5://")) {
        s = s[9..];
    }
    if (std.mem.lastIndexOfScalar(u8, s, '@')) |at| {
        const cred = s[0..at];
        s = s[at + 1 ..];
        if (std.mem.indexOfScalar(u8, cred, ':')) |c| {
            cfg_user_len = @min(c, cfg_user.len);
            @memcpy(cfg_user[0..cfg_user_len], cred[0..cfg_user_len]);
            const pw = cred[c + 1 ..];
            cfg_pass_len = @min(pw.len, cfg_pass.len);
            @memcpy(cfg_pass[0..cfg_pass_len], pw[0..cfg_pass_len]);
        } else {
            cfg_user_len = @min(cred.len, cfg_user.len);
            @memcpy(cfg_user[0..cfg_user_len], cred[0..cfg_user_len]);
        }
    }
    var host = s;
    if (std.mem.lastIndexOfScalar(u8, s, ':')) |c| {
        host = s[0..c];
        cfg_port = std.fmt.parseInt(u16, s[c + 1 ..], 10) catch 1080;
    }
    if (host.len > 1 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
    cfg_host_len = @min(host.len, cfg_host.len);
    @memcpy(cfg_host[0..cfg_host_len], host[0..cfg_host_len]);
    cfg_host[cfg_host_len] = 0;
    cfg_ready = true;
    logf("proxy {s}:{d} user='{s}'", .{ cfg_host[0..cfg_host_len], cfg_port, cfg_user[0..cfg_user_len] });
}

// ---------------------------------------------------------------------------
// proxy address
// ---------------------------------------------------------------------------
var proxy_sa: SockAddrStore = undefined;
var proxy_sa_len: c_int = 0;
var proxy_fam: u16 = 0;
var proxy_state: u8 = 0; // 0 unknown, 1 ok, 2 failed
var proxy_lock: usize = 0;

fn proxyAddress() ?*const sockaddr {
    AcquireSRWLockExclusive(&proxy_lock);
    defer ReleaseSRWLockExclusive(&proxy_lock);
    if (proxy_state == 1) return @ptrCast(&proxy_sa);
    if (proxy_state == 2) return null;
    var hints: addrinfo = std.mem.zeroes(addrinfo);
    hints.family = 0;
    hints.socktype = SOCK_STREAM;
    var port_s: [10]u8 = @splat(0);
    const ps0 = std.fmt.bufPrint(&port_s, "{d}", .{cfg_port}) catch {
        proxy_state = 2;
        return null;
    };
    port_s[ps0.len] = 0;
    const ps: [*:0]const u8 = @ptrCast(&port_s);
    var res: ?*addrinfo = null;
    const rc = real_getaddrinfo(cfg_host[0..cfg_host_len :0], ps, &hints, &res);
    if (rc != 0 or res == null) {
        proxy_state = 2;
        logf("proxy resolve failed rc={d} host={s}", .{ rc, cfg_host[0..cfg_host_len] });
        return null;
    }
    defer real_freeaddrinfo(res);
    var it = res;
    while (it) |ai| : (it = ai.next) {
        const a = ai.addr orelse continue;
        const len: usize = if (ai.addrlen > 0 and ai.addrlen <= 128) ai.addrlen else if (a.family == AF_INET) 16 else 28;
        const src: [*]const u8 = @ptrCast(a);
        const dst: [*]u8 = @ptrCast(&proxy_sa);
        @memcpy(dst[0..len], src[0..len]);
        proxy_sa_len = @intCast(len);
        proxy_fam = a.family;
        proxy_state = 1;
        logf("proxy address family={d} len={d}", .{ a.family, len });
        return @ptrCast(&proxy_sa);
    }
    proxy_state = 2;
    return null;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
fn readBE16(p: [*]const u8) u16 {
    return (@as(u16, p[0]) << 8) | @as(u16, p[1]);
}
fn writeNative16(p: [*]u8, v: u16) void {
    const q: *align(1) u16 = @ptrCast(p);
    q.* = v;
}

fn writeBE16(p: [*]u8, v: u16) void {
    p[0] = @intCast((v >> 8) & 0xff);
    p[1] = @intCast(v & 0xff);
}

const Target = struct {
    fam: u8 = 0,
    ip: [16]u8 = @splat(0),
    name: [256]u8 = @splat(0),
    name_len: u16 = 0,
    port: u16 = 0,
};

fn targetFromSockaddr(sa: ?*const sockaddr, len: c_int) ?Target {
    const p = sa orelse return null;
    if (len < 2) return null;
    var t = Target{};
    const b: [*]const u8 = @ptrCast(p);
    if (p.family == AF_INET) {
        if (len < 16) return null;
        t.fam = 4;
        @memcpy(t.ip[0..4], b[4..8]);
        t.port = readBE16(b + 2);
        if (b[4] == 127 or b[4] == 0) return null;
    } else if (p.family == AF_INET6) {
        if (len < 28) return null;
        @memcpy(t.ip[0..16], b[8..24]);
        t.port = readBE16(b + 2);
        const v4mapped = std.mem.allEqual(u8, b[8..18], 0) and b[18] == 0xff and b[19] == 0xff;
        if (v4mapped) {
            t.fam = 4;
            @memcpy(t.ip[0..4], b[20..24]);
            if (b[20] == 127 or b[20] == 0) return null;
        } else {
            t.fam = 6;
            if (isV6Loopback(b + 8)) return null;
        }
    } else return null;
    return t;
}

fn isV6Loopback(b: [*]const u8) bool {
    var i: usize = 0;
    while (i < 15) : (i += 1) {
        if (b[i] != 0) return false;
    }
    return b[15] == 1;
}

fn sockaddrFromTarget(t: *const Target, out: *SockAddrStore) c_int {
    const b: [*]u8 = @ptrCast(out);
    if (t.fam == 4) {
        @memset(b[0..16], 0);
        writeNative16(b, AF_INET);
        writeBE16(b + 2, t.port);
        @memcpy(b[4..8], t.ip[0..4]);
        return 16;
    }
    @memset(b[0..28], 0);
    writeNative16(b, AF_INET6);
    writeBE16(b + 2, t.port);
    @memcpy(b[8..24], t.ip[0..16]);
    return 28;
}

const NameEntry = struct { used: bool, fam: u8, ip: [16]u8, name: [256]u8, len: u16 };
var name_map: [256]NameEntry = std.mem.zeroes([256]NameEntry);
var name_count: usize = 0;
var name_lock: usize = 0;

fn filterV4(res: *?*addrinfo) void {
    var head: ?*addrinfo = res.*;
    var cur: ?*addrinfo = head;
    var prev: ?*addrinfo = null;
    while (cur) |ai| {
        const a = ai.addr orelse {
            prev = ai;
            cur = ai.next;
            continue;
        };
        if (a.family == AF_INET) {
            if (prev == null) head = ai else prev.?.next = ai;
            prev = ai;
            cur = ai.next;
        } else {
            cur = ai.next;
            if (prev == null) head = cur else prev.?.next = cur;
        }
    }
    res.* = head;
}

fn rememberName(ip_bytes: [*]const u8, fam: u8, name: []const u8) void {
    if (name.len == 0 or name.len > 255) return;
    AcquireSRWLockExclusive(&name_lock);
    defer ReleaseSRWLockExclusive(&name_lock);
    const n: usize = if (fam == 4) 4 else 16;
    var i: usize = 0;
    while (i < name_count) : (i += 1) {
        const e = &name_map[i];
        if (e.used and e.fam == fam and std.mem.eql(u8, e.ip[0..n], ip_bytes[0..n])) {
            e.len = @intCast(name.len);
            @memcpy(e.name[0..name.len], name);
            return;
        }
    }
    const slot: usize = if (name_count < name_map.len) blk: {
        const s = name_count;
        name_count += 1;
        break :blk s;
    } else 0;
    const e = &name_map[slot];
    e.used = true;
    e.fam = fam;
    e.len = @intCast(name.len);
    @memcpy(e.ip[0..n], ip_bytes[0..n]);
    @memcpy(e.name[0..name.len], name);
}

fn lookupName(t: *Target) void {
    t.name_len = 0;
    AcquireSRWLockExclusive(&name_lock);
    defer ReleaseSRWLockExclusive(&name_lock);
    var i: usize = 0;
    while (i < name_count) : (i += 1) {
        const e = &name_map[i];
        if (!e.used) continue;
        const n: usize = if (e.fam == 4) 4 else 16;
        if (e.fam == t.fam and std.mem.eql(u8, e.ip[0..n], t.ip[0..n])) {
            t.name_len = e.len;
            @memcpy(t.name[0..e.len], e.name[0..e.len]);
            return;
        }
        if (e.fam == 6 and t.fam == 4 and std.mem.allEqual(u8, e.ip[0..10], 0) and e.ip[10] == 0xff and e.ip[11] == 0xff and std.mem.eql(u8, e.ip[12..16], t.ip[0..4])) {
            t.name_len = e.len;
            @memcpy(t.name[0..e.len], e.name[0..e.len]);
            return;
        }
    }
}

const IocpEntry = struct { used: bool, sock: SOCKET, port: ?*anyopaque, key: usize };
var iocp_map: [256]IocpEntry = std.mem.zeroes([256]IocpEntry);
var iocp_lock: usize = 0;

fn rememberIocp(s: SOCKET, port: ?*anyopaque, key: usize) void {
    AcquireSRWLockExclusive(&iocp_lock);
    defer ReleaseSRWLockExclusive(&iocp_lock);
    var i: usize = 0;
    while (i < iocp_map.len) : (i += 1) {
        if (iocp_map[i].used and iocp_map[i].sock == s) {
            iocp_map[i].port = port;
            iocp_map[i].key = key;
            return;
        }
    }
    i = 0;
    while (i < iocp_map.len) : (i += 1) {
        if (!iocp_map[i].used) {
            iocp_map[i] = .{ .used = true, .sock = s, .port = port, .key = key };
            return;
        }
    }
}

fn forgetIocp(s: SOCKET) void {
    AcquireSRWLockExclusive(&iocp_lock);
    defer ReleaseSRWLockExclusive(&iocp_lock);
    var i: usize = 0;
    while (i < iocp_map.len) : (i += 1) {
        if (iocp_map[i].used and iocp_map[i].sock == s) iocp_map[i].used = false;
    }
}

fn completeOverlapped(s: SOCKET, ov: *OVERLAPPED, bytes: usize) void {
    ov.internal = 0;
    ov.internal_high = bytes;
    var port: ?*anyopaque = null;
    var key: usize = 0;
    AcquireSRWLockExclusive(&iocp_lock);
    var i: usize = 0;
    while (i < iocp_map.len) : (i += 1) {
        if (iocp_map[i].used and iocp_map[i].sock == s) {
            port = iocp_map[i].port;
            key = iocp_map[i].key;
            break;
        }
    }
    ReleaseSRWLockExclusive(&iocp_lock);
    if (port) |p| _ = PostQueuedCompletionStatus(p, @intCast(bytes), key, ov);
}

fn sockType(s: SOCKET) c_int {
    var v: c_int = 0;
    var l: c_int = 4;
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, @ptrCast(&v), &l) != 0) return 0;
    return v;
}

fn sockFamily(s: SOCKET) u16 {
    var ss: SockAddrStore = undefined;
    var l: c_int = 128;
    if (getsockname(s, @ptrCast(&ss), &l) != 0) return 0;
    const p: *const sockaddr = @ptrCast(&ss);
    return p.family;
}

fn setTimeouts(s: SOCKET, ms: u32) void {
    var v: u32 = ms;
    _ = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, @ptrCast(&v), 4);
    _ = setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, @ptrCast(&v), 4);
}

fn sendAll(s: SOCKET, p: []const u8) bool {
    var off: usize = 0;
    while (off < p.len) {
        const n = real_send(s, p[off..].ptr, @intCast(p.len - off), 0);
        if (n <= 0) return false;
        off += @intCast(n);
    }
    return true;
}

fn recvAll(s: SOCKET, p: []u8) bool {
    var off: usize = 0;
    while (off < p.len) {
        const n = real_recv(s, p[off..].ptr, @intCast(p.len - off), 0);
        if (n <= 0) return false;
        off += @intCast(n);
    }
    return true;
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------
fn socksGreeting(ps: SOCKET) bool {
    if (cfg_user_len > 0) {
        const g = [_]u8{ 5, 2, 0, 2 };
        if (!sendAll(ps, &g)) return false;
        var r: [2]u8 = undefined;
        if (!recvAll(ps, &r)) return false;
        if (r[0] != 5) return false;
        if (r[1] == 0) return true;
        if (r[1] != 2) return false;
        var a: [300]u8 = undefined;
        a[0] = 1;
        a[1] = @intCast(cfg_user_len);
        @memcpy(a[2 .. 2 + cfg_user_len], cfg_user[0..cfg_user_len]);
        var n: usize = 2 + cfg_user_len;
        a[n] = @intCast(cfg_pass_len);
        @memcpy(a[n + 1 .. n + 1 + cfg_pass_len], cfg_pass[0..cfg_pass_len]);
        n += 1 + cfg_pass_len;
        if (!sendAll(ps, a[0..n])) return false;
        var ar: [2]u8 = undefined;
        if (!recvAll(ps, &ar)) return false;
        return ar[1] == 0;
    }
    const g = [_]u8{ 5, 1, 0 };
    if (!sendAll(ps, &g)) return false;
    var r: [2]u8 = undefined;
    if (!recvAll(ps, &r)) return false;
    return r[0] == 5 and r[1] == 0;
}

fn buildRequest(t: *const Target, cmd: u8, out: []u8) usize {
    out[0] = 5;
    out[1] = cmd;
    out[2] = 0;
    var n: usize = 3;
    if (t.name_len > 0) {
        out[n] = 3;
        out[n + 1] = @intCast(t.name_len);
        @memcpy(out[n + 2 .. n + 2 + t.name_len], t.name[0..t.name_len]);
        n += 2 + t.name_len;
    } else if (t.fam == 4) {
        out[n] = 1;
        @memcpy(out[n + 1 .. n + 5], t.ip[0..4]);
        n += 5;
    } else {
        out[n] = 4;
        @memcpy(out[n + 1 .. n + 17], t.ip[0..16]);
        n += 17;
    }
    writeBE16(out[n..].ptr, t.port);
    return n + 2;
}

const SocksReply = struct { rep: u8, len: c_int };

fn readSocksReply(ps: SOCKET, out_ss: ?*SockAddrStore) SocksReply {
    var h: [4]u8 = undefined;
    if (!recvAll(ps, &h)) return .{ .rep = 0xff, .len = 0 };
    if (h[0] != 5) return .{ .rep = 0xff, .len = 0 };
    var alen: usize = 0;
    switch (h[3]) {
        1 => alen = 4,
        4 => alen = 16,
        3 => {
            var l: [1]u8 = undefined;
            if (!recvAll(ps, &l)) return .{ .rep = 0xff, .len = 0 };
            alen = l[0];
        },
        else => return .{ .rep = 0xff, .len = 0 },
    }
    var tail: [2 + 256]u8 = undefined;
    if (!recvAll(ps, tail[0 .. alen + 2])) return .{ .rep = 0xff, .len = 0 };
    if (out_ss) |ss| {
        const b: [*]u8 = @ptrCast(ss);
        @memset(b[0..28], 0);
        if (h[3] == 3) {
            // domain bind address: the relay lives on the proxy host
            if (proxyAddress()) |pa| {
                const pb: [*]const u8 = @ptrCast(pa);
                const pl: usize = if (pa.family == AF_INET) 16 else 28;
                @memcpy(b[0..pl], pb[0..pl]);
                @memcpy(b[2..4], tail[alen .. alen + 2]); // reply port
                return .{ .rep = h[1], .len = @intCast(pl) };
            }
        }
        if (h[3] == 1) {
            writeNative16(b, AF_INET);
            @memcpy(b[2..4], tail[alen .. alen + 2]);
            @memcpy(b[4..8], tail[0..4]);
            return .{ .rep = h[1], .len = 16 };
        }
        if (h[3] == 4) {
            writeNative16(b, AF_INET6);
            @memcpy(b[2..4], tail[alen .. alen + 2]);
            @memcpy(b[8..24], tail[0..16]);
            return .{ .rep = h[1], .len = 28 };
        }
    }
    return .{ .rep = h[1], .len = 0 };
}

fn tcpTunnelToProxy(ps: SOCKET, t: *const Target) bool {
    if (!socksGreeting(ps)) {
        logRaw("socks greeting failed");
        return false;
    }
    var req: [320]u8 = undefined;
    const n = buildRequest(t, 1, &req);
    if (!sendAll(ps, req[0..n])) return false;
    const r = readSocksReply(ps, null);
    if (r.rep != 0) {
        logf("socks connect rejected rep={d}", .{r.rep});
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// TCP relay
// ---------------------------------------------------------------------------
const ConnCtx = struct { listener: SOCKET, app: SOCKET, target: Target };

fn relayPump(a: SOCKET, b: SOCKET) void {
    const heap = GetProcessHeap();
    const sz: usize = 16384;
    const raw = HeapAlloc(heap, 0, sz) orelse {
        _ = extern_closesocket(a);
        _ = extern_closesocket(b);
        return;
    };
    defer _ = HeapFree(heap, 0, raw);
    const p: [*]u8 = @ptrCast(raw);
    var fds = [2]WSAPOLLFD{
        .{ .fd = a, .events = POLLRDNORM, .revents = 0 },
        .{ .fd = b, .events = POLLRDNORM, .revents = 0 },
    };
    while (true) {
        fds[0].revents = 0;
        fds[1].revents = 0;
        const rc = WSAPoll(&fds, 2, -1);
        if (rc <= 0) break;
        if ((fds[0].revents & POLLRDNORM) != 0) {
            const n = real_recv(a, p, @intCast(sz), 0);
            if (n <= 0) break;
            if (!sendAll(b, p[0..@intCast(n)])) break;
        }
        if ((fds[1].revents & POLLRDNORM) != 0) {
            const n = real_recv(b, p, @intCast(sz), 0);
            if (n <= 0) break;
            if (!sendAll(a, p[0..@intCast(n)])) break;
        }
    }
    _ = extern_closesocket(a);
    _ = extern_closesocket(b);
}

extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;
const extern_closesocket = closesocket;

fn tcpRelayThread(arg: ?*anyopaque) callconv(.winapi) u32 {
    const ctx: *ConnCtx = @ptrCast(@alignCast(arg));
    defer _ = HeapFree(GetProcessHeap(), 0, ctx);
    logf("relay: enter sock={d}", .{ctx.app});
    var ss: SockAddrStore = undefined;
    var sl: c_int = 128;
    const cs = accept(ctx.listener, @ptrCast(&ss), &sl);
    _ = extern_closesocket(ctx.listener);
    if (cs == INVALID_SOCKET) {
        logRaw("relay: accept failed");
        return 0;
    }
    logf("relay: accepted cs={d}", .{cs});
    const pa = proxyAddress() orelse {
        _ = extern_closesocket(cs);
        logRaw("relay: proxy address unavailable");
        return 0;
    };
    logf("relay: got proxy addr fam={d}", .{proxy_fam});
    const fam: c_int = if (proxy_fam == AF_INET6) AF_INET6 else AF_INET;
    const ps = socket(fam, SOCK_STREAM, 0);
    if (ps == INVALID_SOCKET) {
        _ = extern_closesocket(cs);
        return 0;
    }
    setTimeouts(ps, 10000);
    logf("relay: connecting to proxy", .{});
    if (real_connect(ps, pa, proxy_sa_len) != 0) {
        logf("relay: proxy connect failed err={d}", .{WSAGetLastError()});
        _ = extern_closesocket(ps);
        _ = extern_closesocket(cs);
        return 0;
    }
    var t = ctx.target;
    lookupName(&t);
    logf("relay: greeting proxy", .{});
    if (!tcpTunnelToProxy(ps, &t)) {
        _ = extern_closesocket(ps);
        _ = extern_closesocket(cs);
        return 0;
    }
    setTimeouts(ps, 0);
    logf("tcp tunnel established -> {s}:{d}", .{ if (t.name_len > 0) t.name[0..t.name_len] else "numeric", t.port });
    relayPump(cs, ps);
    return 0;
}

fn isProxySelf(t: *const Target) bool {
    if (t.port != cfg_port) return false;
    const pa = proxyAddress() orelse return false;
    const pb: [*]const u8 = @ptrCast(pa);
    if (pa.family == AF_INET and t.fam == 4) {
        return std.mem.eql(u8, t.ip[0..4], pb[4..8]);
    }
    if (pa.family == AF_INET6 and t.fam == 6) {
        return std.mem.eql(u8, t.ip[0..16], pb[8..24]);
    }
    return false;
}

fn tcpConnect(s: SOCKET, t: *const Target, name: ?*const sockaddr, namelen: c_int) c_int {
    const fam = sockFamily(s);
    const lfam: c_int = if (fam == AF_INET6) AF_INET6 else AF_INET;
    const ls = socket(lfam, SOCK_STREAM, 0);
    if (ls == INVALID_SOCKET) {
        if (verbose) logf("tcp: listener socket failed err={d}", .{WSAGetLastError()});
        return real_connect(s, name, namelen);
    }

    var la: SockAddrStore = undefined;
    const b: [*]u8 = @ptrCast(&la);
    @memset(b[0..64], 0);
    var llen: c_int = undefined;
    if (lfam == AF_INET6) {
        writeNative16(b, AF_INET6);
        b[8 + 15] = 1;
        llen = 28;
    } else {
        writeNative16(b, AF_INET);
        b[4] = 127;
        b[5] = 0;
        b[6] = 0;
        b[7] = 1;
        llen = 16;
    }
    if (bind(ls, @ptrCast(&la), llen) != 0) {
        if (verbose) logf("tcp: listener bind failed err={d} fam={d}", .{ WSAGetLastError(), fam });
        _ = extern_closesocket(ls);
        return real_connect(s, name, namelen);
    }
    if (listen(ls, 1) != 0) {
        if (verbose) logf("tcp: listener listen failed err={d}", .{WSAGetLastError()});
        _ = extern_closesocket(ls);
        return real_connect(s, name, namelen);
    }
    var got: SockAddrStore = undefined;
    var gl: c_int = 128;
    if (getsockname(ls, @ptrCast(&got), &gl) != 0) {
        _ = extern_closesocket(ls);
        return real_connect(s, name, namelen);
    }
    const mem = HeapAlloc(GetProcessHeap(), 0x8, @sizeOf(ConnCtx)) orelse {
        _ = extern_closesocket(ls);
        return real_connect(s, name, namelen);
    };
    const ctx: *ConnCtx = @ptrCast(@alignCast(mem));
    ctx.* = .{ .listener = ls, .app = s, .target = t.* };
    _ = CreateThread(null, 0, tcpRelayThread, ctx, 0, null);
    logf("tcp redirect {s}:{d}", .{ if (t.name_len > 0) t.name[0..t.name_len] else "numeric", t.port });
    return real_connect(s, @ptrCast(&got), gl);
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------
const UdpCtx = struct {
    used: bool,
    app: SOCKET,
    ctrl: SOCKET,
    relay: SockAddrStore,
    relay_len: c_int,
    relay_fam: u16,
    target: Target,
};
var udp_ctxs: [64]UdpCtx = std.mem.zeroes([64]UdpCtx);
var udp_lock: usize = 0;

fn udpFindLocked(s: SOCKET) ?*UdpCtx {
    var i: usize = 0;
    while (i < udp_ctxs.len) : (i += 1) {
        if (udp_ctxs[i].used and udp_ctxs[i].app == s) return &udp_ctxs[i];
    }
    return null;
}

fn udpAssociate(ctrl: SOCKET, out: *SockAddrStore, out_len: *c_int) bool {
    if (!socksGreeting(ctrl)) return false;
    const req = [_]u8{ 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 };
    if (!sendAll(ctrl, &req)) return false;
    const r = readSocksReply(ctrl, out);
    if (r.rep != 0 or r.len == 0) {
        logf("udp associate rejected rep={d}", .{r.rep});
        return false;
    }
    out_len.* = r.len;
    const b: [*]u8 = @ptrCast(out);
    if (r.len == 16) {
        const bnd_zero = b[4] == 0 and b[5] == 0 and b[6] == 0 and b[7] == 0;
        const bnd_loop = b[4] == 127;
        const pa = proxyAddress();
        var proxy_loop = false;
        if (pa) |paddr| {
            const pb: [*]const u8 = @ptrCast(paddr);
            proxy_loop = pb[4] == 127;
        }
        if (bnd_zero or (bnd_loop and proxy_loop)) {
            if (pa) |paddr| {
                const pb: [*]const u8 = @ptrCast(paddr);
                @memcpy(b[4..8], pb[4..8]);
            }
        } else if (bnd_loop) {
            logRaw("udp: proxy returned a loopback relay address, UDP relay not reachable; using direct UDP");
            return false;
        }
    }
    return true;
}

fn udpEnsure(s: SOCKET, t: *const Target) ?*UdpCtx {
    AcquireSRWLockExclusive(&udp_lock);
    defer ReleaseSRWLockExclusive(&udp_lock);
    if (udpFindLocked(s)) |c| {
        c.target = t.*;
        return c;
    }
    const pa = proxyAddress() orelse return null;
    const fam: c_int = if (proxy_fam == AF_INET6) AF_INET6 else AF_INET;
    const ctrl = socket(fam, SOCK_STREAM, 0);
    if (ctrl == INVALID_SOCKET) return null;
    setTimeouts(ctrl, 8000);
    if (real_connect(ctrl, pa, proxy_sa_len) != 0) {
        _ = extern_closesocket(ctrl);
        return null;
    }
    var relay: SockAddrStore = undefined;
    var rlen: c_int = 0;
    if (!udpAssociate(ctrl, &relay, &rlen)) {
        _ = extern_closesocket(ctrl);
        return null;
    }
    setTimeouts(ctrl, 0);
    var slot: ?*UdpCtx = null;
    var i: usize = 0;
    while (i < udp_ctxs.len) : (i += 1) {
        if (!udp_ctxs[i].used) {
            slot = &udp_ctxs[i];
            break;
        }
    }
    const c = slot orelse {
        _ = extern_closesocket(ctrl);
        return null;
    };
    const rf: u16 = (@as(u16, @as([*]const u8, @ptrCast(&relay))[0]) << 0);
    _ = rf;
    c.* = .{ .used = true, .app = s, .ctrl = ctrl, .relay = relay, .relay_len = rlen, .relay_fam = @as(*const sockaddr, @ptrCast(&relay)).family, .target = t.* };
    logf("udp associated socket={d} relayfamily={d}", .{ s, c.relay_fam });
    return c;
}

fn udpDrop(s: SOCKET) void {
    AcquireSRWLockExclusive(&udp_lock);
    defer ReleaseSRWLockExclusive(&udp_lock);
    var i: usize = 0;
    while (i < udp_ctxs.len) : (i += 1) {
        if (udp_ctxs[i].used and udp_ctxs[i].app == s) {
            _ = extern_closesocket(udp_ctxs[i].ctrl);
            udp_ctxs[i].used = false;
        }
    }
}

fn wrapDatagram(t: *const Target, payload: []const u8, out: []u8) usize {
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    var n: usize = 3;
    if (t.fam == 4) {
        out[n] = 1;
        @memcpy(out[n + 1 .. n + 5], t.ip[0..4]);
        n += 5;
    } else {
        out[n] = 4;
        @memcpy(out[n + 1 .. n + 17], t.ip[0..16]);
        n += 17;
    }
    writeBE16(out[n..].ptr, t.port);
    n += 2;
    @memcpy(out[n .. n + payload.len], payload);
    return n + payload.len;
}

const DatagramHeader = struct { consumed: usize, t: Target };

fn parseDatagramHeader(p: []const u8) ?DatagramHeader {
    if (p.len < 4 or p[0] != 0 or p[1] != 0) return null;
    var t = Target{};
    var off: usize = 4;
    if (p[3] == 1) {
        if (p.len < off + 6) return null;
        t.fam = 4;
        @memcpy(t.ip[0..4], p[off .. off + 4]);
        off += 4;
    } else if (p[3] == 4) {
        if (p.len < off + 18) return null;
        t.fam = 6;
        @memcpy(t.ip[0..16], p[off .. off + 16]);
        off += 16;
    } else if (p[3] == 3) {
        if (p.len < off + 1) return null;
        const nl = p[off];
        if (p.len < off + 1 + nl + 2) return null;
        t.fam = 3;
        t.name_len = @intCast(nl);
        @memcpy(t.name[0..nl], p[off + 1 .. off + 1 + nl]);
        off += 1 + nl;
    } else return null;
    t.port = readBE16(p[off..].ptr);
    return .{ .consumed = off + 2, .t = t };
}

fn udpSendTo(s: SOCKET, payload: []const u8, t: *const Target) c_int {
    const c = udpEnsure(s, t) orelse return -1;
    if (sockFamily(s) == AF_INET6 and c.relay_fam == AF_INET) {
        logRaw("udp: relay family mismatch, datagram dropped");
        return -1;
    }
    const heap = GetProcessHeap();
    const total = payload.len + 22;
    const raw = HeapAlloc(heap, 0, total) orelse return -1;
    defer _ = HeapFree(heap, 0, raw);
    const p: [*]u8 = @ptrCast(raw);
    const n = wrapDatagram(t, payload, p[0..total]);
    const rc = real_sendto(s, p, @intCast(n), 0, @ptrCast(&c.relay), c.relay_len);
    if (rc < 0) {
        logf("udp relay send failed err={d}", .{WSAGetLastError()});
        return -1;
    }
    return @intCast(payload.len);
}

fn udpSendConnected(s: SOCKET, payload: []const u8) c_int {
    var t = Target{};
    var relay: SockAddrStore = undefined;
    var relay_len: c_int = 0;
    var relay_fam: u16 = 0;
    AcquireSRWLockExclusive(&udp_lock);
    if (udpFindLocked(s)) |c| {
        t = c.target;
        relay = c.relay;
        relay_len = c.relay_len;
        relay_fam = c.relay_fam;
    } else {
        ReleaseSRWLockExclusive(&udp_lock);
        return -1;
    }
    ReleaseSRWLockExclusive(&udp_lock);
    if (sockFamily(s) == AF_INET6 and relay_fam == AF_INET) return -1;
    const heap = GetProcessHeap();
    const total = payload.len + 22;
    const raw = HeapAlloc(heap, 0, total) orelse return -1;
    defer _ = HeapFree(heap, 0, raw);
    const p: [*]u8 = @ptrCast(raw);
    const n = wrapDatagram(&t, payload, p[0..total]);
    const rc = real_send(s, p, @intCast(n), 0);
    if (rc < 0) return -1;
    return @intCast(payload.len);
}

fn isRelaySource(s: SOCKET, from: ?*const sockaddr) bool {
    const f = from orelse return false;
    AcquireSRWLockExclusive(&udp_lock);
    defer ReleaseSRWLockExclusive(&udp_lock);
    const c = udpFindLocked(s) orelse return false;
    if (f.family != c.relay_fam) return false;
    const a: [*]const u8 = @ptrCast(f);
    const b: [*]const u8 = @ptrCast(&c.relay);
    const n: usize = if (f.family == AF_INET) 8 else 24;
    return std.mem.eql(u8, a[2..n], b[2..n]);
}

// ---------------------------------------------------------------------------
// deferred UDP read rewriting (completion-time, no blocking on IOCP sockets)
// ---------------------------------------------------------------------------
const RecvOp = struct {
    used: bool,
    ov: usize,
    sock: SOCKET,
    nbuf: u32,
    bufs: [8]WSABUF,
    from: ?*sockaddr,
    fromlen: ?*c_int,
};
var recv_ops: [128]RecvOp = @splat(.{ .used = false, .ov = 0, .sock = 0, .nbuf = 0, .bufs = @splat(.{ .len = 0, .buf = null }), .from = null, .fromlen = null });
var recv_lock: usize = 0;

fn hasUdpCtx(s: SOCKET) bool {
    AcquireSRWLockExclusive(&udp_lock);
    defer ReleaseSRWLockExclusive(&udp_lock);
    return udpFindLocked(s) != null;
}

fn rememberRecvOp(ov: *OVERLAPPED, s: SOCKET, bufs: ?[*]WSABUF, count: u32, from: ?*sockaddr, fromlen: ?*c_int) void {
    AcquireSRWLockExclusive(&recv_lock);
    defer ReleaseSRWLockExclusive(&recv_lock);
    var slot: ?*RecvOp = null;
    var i: usize = 0;
    while (i < recv_ops.len) : (i += 1) {
        if (!recv_ops[i].used) {
            slot = &recv_ops[i];
            break;
        }
    }
    const e = slot orelse return;
    e.used = true;
    e.ov = @intFromPtr(ov);
    e.sock = s;
    const n: u32 = @min(count, 8);
    e.nbuf = n;
    var k: u32 = 0;
    while (k < n) : (k += 1) e.bufs[k] = bufs.?[k];
    e.from = from;
    e.fromlen = fromlen;
}

fn takeRecvOp(ov: ?*OVERLAPPED) ?RecvOp {
    const q = ov orelse return null;
    const key = @intFromPtr(q);
    AcquireSRWLockExclusive(&recv_lock);
    defer ReleaseSRWLockExclusive(&recv_lock);
    var i: usize = 0;
    while (i < recv_ops.len) : (i += 1) {
        if (recv_ops[i].used and recv_ops[i].ov == key) {
            var copy = recv_ops[i];
            recv_ops[i].used = false;
            copy.used = false;
            return copy;
        }
    }
    return null;
}

fn rewriteRecv(op: RecvOp, bytes: u32) u32 {
    if (bytes == 0) return 0;
    if (op.bufs[0].buf == null) return bytes;
    const first_len = @min(@as(usize, op.bufs[0].len), @as(usize, bytes));
    if (first_len < 4) return bytes;
    const hdr = parseDatagramHeader(op.bufs[0].buf.?[0..first_len]) orelse return bytes;
    if (bytes <= hdr.consumed) return 0;
    const payload_len: usize = bytes - hdr.consumed;
    if (op.nbuf == 1) {
        const dst = op.bufs[0].buf.?;
        std.mem.copyForwards(u8, dst[0..payload_len], dst[hdr.consumed .. hdr.consumed + payload_len]);
    } else {
        const heap = GetProcessHeap();
        const raw = HeapAlloc(heap, 0, payload_len) orelse return bytes;
        defer _ = HeapFree(heap, 0, raw);
        const tmp: [*]u8 = @ptrCast(raw);
        var copied: usize = 0;
        var off: usize = hdr.consumed;
        var bi: u32 = 0;
        while (bi < op.nbuf and copied < payload_len) : (bi += 1) {
            const blen: usize = op.bufs[bi].len;
            if (op.bufs[bi].buf == null or blen == 0) continue;
            if (off >= blen) {
                off -= blen;
                continue;
            }
            const take = @min(blen - off, payload_len - copied);
            @memcpy(tmp[copied .. copied + take], op.bufs[bi].buf.?[off .. off + take]);
            copied += take;
            off = 0;
        }
        var d: usize = 0;
        bi = 0;
        while (bi < op.nbuf and d < copied) : (bi += 1) {
            const blen: usize = op.bufs[bi].len;
            if (op.bufs[bi].buf == null or blen == 0) continue;
            const take = @min(blen, copied - d);
            @memcpy(op.bufs[bi].buf.?[0..take], tmp[d .. d + take]);
            d += take;
        }
    }
    if (op.from) |fp| {
        var store: SockAddrStore = undefined;
        const l = sockaddrFromTarget(&hdr.t, &store);
        const fb: [*]u8 = @ptrCast(fp);
        @memcpy(fb[0..@intCast(l)], @as([*]const u8, @ptrCast(&store))[0..@intCast(l)]);
        if (op.fromlen) |fl| fl.* = l;
    }
    return @intCast(payload_len);
}

fn hook_gqcs(port: ?*anyopaque, bytes: *u32, key: *usize, ov: *?*OVERLAPPED, ms: u32) callconv(.winapi) i32 {
    const rc = real_gqcs(port, bytes, key, ov, ms);
    if (rc != 0) {
        if (ov.*) |o| {
            if (takeRecvOp(o)) |op| bytes.* = rewriteRecv(op, bytes.*);
        }
    }
    return rc;
}

fn hook_gqcsex(port: ?*anyopaque, entries: [*]OVERLAPPED_ENTRY, max: u32, removed: *u32, ms: u32) callconv(.winapi) i32 {
    const rc = real_gqcsex(port, entries, max, removed, ms);
    if (rc != 0) {
        var i: u32 = 0;
        while (i < removed.*) : (i += 1) {
            const e = &entries[i];
            if (e.ov) |o| {
                if (takeRecvOp(o)) |op| e.bytes = rewriteRecv(op, e.bytes);
            }
        }
    }
    return rc;
}

// ---------------------------------------------------------------------------
// hooks
// ---------------------------------------------------------------------------
fn copyToBufsSingle(buf: [*]u8, cap: usize, src: []const u8) usize {
    const n = @min(cap, src.len);
    @memcpy(buf[0..n], src[0..n]);
    return n;
}

fn flattenBufs(bufs: ?[*]WSABUF, count: u32, out: []u8) usize {
    var n: usize = 0;
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const b = bufs.?[i];
        if (b.buf == null or b.len == 0) continue;
        const take = @min(@as(usize, b.len), out.len - n);
        if (take == 0) break;
        @memcpy(out[n .. n + take], b.buf.?[0..take]);
        n += take;
    }
    return n;
}

fn copyToBufs(bufs: ?[*]WSABUF, count: u32, src: []const u8) usize {
    var n: usize = 0;
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const b = bufs.?[i];
        if (b.buf == null or b.len == 0) continue;
        if (n >= src.len) break;
        const take = @min(@as(usize, b.len), src.len - n);
        @memcpy(b.buf.?[0..take], src[n .. n + take]);
        n += take;
    }
    return n;
}

const SO_UPDATE_CONNECT_CONTEXT: c_int = 0x7010;

fn hook_connectex(s: SOCKET, name: ?*const sockaddr, namelen: c_int, sendbuf: ?*anyopaque, sendlen: u32, sent: ?*u32, ov: ?*OVERLAPPED) callconv(.winapi) i32 {
    if (!cfg_enabled) return real_connectex(s, name, namelen, sendbuf, sendlen, sent, ov);
    const t = targetFromSockaddr(name, namelen) orelse return real_connectex(s, name, namelen, sendbuf, sendlen, sent, ov);
    logf("connectEx attempt {s}:{d}", .{ if (t.fam == 4) "ipv4" else "ipv6", t.port });
    const rc = tcpConnect(s, &t, name, namelen);
    if (rc != 0) {
        const e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK) return 0; // FALSE: caller observes the error
    }
    var opt: [1]u8 = .{0};
    _ = setsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, &opt, 0);
    if (sendlen > 0 and sendbuf != null) {
        _ = real_send(s, @ptrCast(sendbuf.?), @intCast(sendlen), 0);
        if (sent) |sp| sp.* = sendlen;
    }
    if (ov) |o| {
        completeOverlapped(s, o, 0);
        if (rc == 0) return 1; // completed synchronously, completion still queued
        WSASetLastError(WSAEWOULDBLOCK);
        return 0; // pending, completion queued
    }
    return 1;
}

fn hook_wsaioctl(s: SOCKET, code: u32, inb: ?*anyopaque, inl: u32, outb: ?*anyopaque, outl: u32, bytes: ?*u32, ov: ?*OVERLAPPED, cr: ?*anyopaque) callconv(.winapi) c_int {
    if (cfg_enabled and code == SIO_GET_EXTENSION_FUNCTION_POINTER and inb != null and inl >= 16 and outb != null and outl >= @sizeOf(usize)) {
        const g: [*]const u8 = @ptrCast(inb.?);
        if (std.mem.eql(u8, g[0..16], WSAID_CONNECTEX[0..16])) {
            const p: *usize = @ptrCast(@alignCast(outb.?));
            p.* = @intFromPtr(&hook_connectex);
            if (bytes) |b| b.* = @sizeOf(usize);
            logRaw("WSAIoctl: ConnectEx -> hook");
            return 0;
        }
    }
    return real_wsaioctl(s, code, inb, inl, outb, outl, bytes, ov, cr);
}

fn hook_connect(s: SOCKET, name: ?*const sockaddr, namelen: c_int) callconv(.winapi) c_int {
    if (!cfg_enabled) return real_connect(s, name, namelen);
    const t = targetFromSockaddr(name, namelen) orelse return real_connect(s, name, namelen);
    if (isProxySelf(&t)) {
        if (verbose) logf("connect to proxy itself {d}:{d}, direct", .{ t.fam, t.port });
        return real_connect(s, name, namelen);
    }
    if (verbose) logf("connect hook fam={d} port={d} type={d}", .{ t.fam, t.port, sockType(s) });
    if (sockType(s) == SOCK_DGRAM) {
        const c = udpEnsure(s, &t) orelse return real_connect(s, name, namelen);
        const rc = real_connect(s, @ptrCast(&c.relay), c.relay_len);
        if (rc != 0) logf("udp connect to relay failed err={d}", .{WSAGetLastError()});
        return rc;
    }
    return tcpConnect(s, &t, name, namelen);
}

fn hook_wsaconnect(s: SOCKET, name: ?*const sockaddr, namelen: c_int, cd: ?*anyopaque, cad: ?*anyopaque, sq: ?*anyopaque, gq: ?*anyopaque) callconv(.winapi) c_int {
    _ = cd;
    _ = cad;
    _ = sq;
    _ = gq;
    return hook_connect(s, name, namelen);
}

fn hook_sendto(s: SOCKET, buf: ?[*]const u8, len: c_int, flags: c_int, to: ?*const sockaddr, tolen: c_int) callconv(.winapi) c_int {
    if (!cfg_enabled or buf == null or len <= 0) return real_sendto(s, buf, len, flags, to, tolen);
    const t = targetFromSockaddr(to, tolen) orelse return real_sendto(s, buf, len, flags, to, tolen);
    if (sockType(s) != SOCK_DGRAM) return real_sendto(s, buf, len, flags, to, tolen);
    const rc = udpSendTo(s, buf.?[0..@intCast(len)], &t);
    if (rc < 0) return real_sendto(s, buf, len, flags, to, tolen);
    return rc;
}

fn hook_wsasendto(s: SOCKET, bufs: ?[*]WSABUF, count: u32, sent: ?*u32, flags: u32, to: ?*const sockaddr, tolen: c_int, ov: ?*OVERLAPPED, cr: ?*anyopaque) callconv(.winapi) c_int {
    if (!cfg_enabled or bufs == null or ov == null) return real_wsasendto(s, bufs, count, sent, flags, to, tolen, ov, cr);
    const t = targetFromSockaddr(to, tolen) orelse return real_wsasendto(s, bufs, count, sent, flags, to, tolen, ov, cr);
    if (sockType(s) != SOCK_DGRAM) return real_wsasendto(s, bufs, count, sent, flags, to, tolen, ov, cr);
    const heap = GetProcessHeap();
    const raw = HeapAlloc(heap, 0, 65568) orelse return real_wsasendto(s, bufs, count, sent, flags, to, tolen, ov, cr);
    defer _ = HeapFree(heap, 0, raw);
    const payload: [*]u8 = @ptrCast(raw);
    const plen = flattenBufs(bufs, count, payload[0..65536]);
    const rc = udpSendTo(s, payload[0..plen], &t);
    if (rc < 0) return real_wsasendto(s, bufs, count, sent, flags, to, tolen, ov, cr);
    if (sent) |sp| sp.* = @intCast(rc);
    completeOverlapped(s, ov.?, @intCast(rc));
    return 0;
}

fn hook_wsasend(s: SOCKET, bufs: ?[*]WSABUF, count: u32, sent: ?*u32, flags: u32, ov: ?*OVERLAPPED, cr: ?*anyopaque) callconv(.winapi) c_int {
    if (!cfg_enabled or bufs == null or ov == null or sockType(s) != SOCK_DGRAM) return real_wsasend(s, bufs, count, sent, flags, ov, cr);
    const heap = GetProcessHeap();
    const raw = HeapAlloc(heap, 0, 65568) orelse return real_wsasend(s, bufs, count, sent, flags, ov, cr);
    defer _ = HeapFree(heap, 0, raw);
    const payload: [*]u8 = @ptrCast(raw);
    const plen = flattenBufs(bufs, count, payload[0..65536]);
    const rc = udpSendConnected(s, payload[0..plen]);
    if (rc < 0) return real_wsasend(s, bufs, count, sent, flags, ov, cr);
    if (sent) |sp| sp.* = @intCast(rc);
    completeOverlapped(s, ov.?, @intCast(rc));
    return 0;
}

fn hook_send(s: SOCKET, buf: ?[*]const u8, len: c_int, flags: c_int) callconv(.winapi) c_int {
    if (!cfg_enabled or buf == null or len <= 0 or sockType(s) != SOCK_DGRAM) return real_send(s, buf, len, flags);
    const rc = udpSendConnected(s, buf.?[0..@intCast(len)]);
    if (rc < 0) return real_send(s, buf, len, flags);
    return rc;
}

fn hook_recvfrom(s: SOCKET, buf: ?[*]u8, len: c_int, flags: c_int, from: ?*sockaddr, fromlen: ?*c_int) callconv(.winapi) c_int {
    if (!cfg_enabled or buf == null or len <= 0 or sockType(s) != SOCK_DGRAM) return real_recvfrom(s, buf, len, flags, from, fromlen);
    const heap = GetProcessHeap();
    const raw = HeapAlloc(heap, 0, 65568) orelse return real_recvfrom(s, buf, len, flags, from, fromlen);
    defer _ = HeapFree(heap, 0, raw);
    const p: [*]u8 = @ptrCast(raw);
    var ss: SockAddrStore = undefined;
    var sl: c_int = 128;
    const n = real_recvfrom(s, p, 65536, 0, @ptrCast(&ss), &sl);
    if (n < 0) return n;
    const data = p[0..@intCast(n)];
    var payload = data;
    var src: ?Target = null;
    if (isRelaySource(s, @ptrCast(&ss))) {
        if (parseDatagramHeader(data)) |hdr| {
            payload = data[hdr.consumed..];
            src = hdr.t;
        }
    }
    const copied = copyToBufsSingle(buf.?, @intCast(len), payload);
    if (from) |fp| {
        const fb: [*]u8 = @ptrCast(fp);
        if (src) |t| {
            var store: SockAddrStore = undefined;
            const l = sockaddrFromTarget(&t, &store);
            @memcpy(fb[0..@intCast(l)], @as([*]const u8, @ptrCast(&store))[0..@intCast(l)]);
            if (fromlen) |fl| fl.* = l;
        } else {
            @memcpy(fb[0..@intCast(sl)], @as([*]const u8, @ptrCast(&ss))[0..@intCast(sl)]);
            if (fromlen) |fl| fl.* = sl;
        }
    }
    return @intCast(copied);
}

fn hook_wsarecvfrom(s: SOCKET, bufs: ?[*]WSABUF, count: u32, recvd: ?*u32, flags: ?*u32, from: ?*sockaddr, fromlen: ?*c_int, ov: ?*OVERLAPPED, cr: ?*anyopaque) callconv(.winapi) c_int {
    if (!cfg_enabled or bufs == null or ov == null or sockType(s) != SOCK_DGRAM) return real_wsarecvfrom(s, bufs, count, recvd, flags, from, fromlen, ov, cr);
    if (!hasUdpCtx(s)) return real_wsarecvfrom(s, bufs, count, recvd, flags, from, fromlen, ov, cr);
    rememberRecvOp(ov.?, s, bufs, count, from, fromlen);
    return real_wsarecvfrom(s, bufs, count, recvd, flags, from, fromlen, ov, cr);
}

fn hook_wsarecv(s: SOCKET, bufs: ?[*]WSABUF, count: u32, recvd: ?*u32, flags: ?*u32, ov: ?*OVERLAPPED, cr: ?*anyopaque) callconv(.winapi) c_int {
    if (!cfg_enabled or bufs == null or ov == null or sockType(s) != SOCK_DGRAM) return real_wsarecv(s, bufs, count, recvd, flags, ov, cr);
    if (!hasUdpCtx(s)) return real_wsarecv(s, bufs, count, recvd, flags, ov, cr);
    rememberRecvOp(ov.?, s, bufs, count, null, null);
    return real_wsarecv(s, bufs, count, recvd, flags, ov, cr);
}

fn hook_recv(s: SOCKET, buf: ?[*]u8, len: c_int, flags: c_int) callconv(.winapi) c_int {
    if (!cfg_enabled or buf == null or len <= 0 or sockType(s) != SOCK_DGRAM) return real_recv(s, buf, len, flags);
    const heap = GetProcessHeap();
    const raw = HeapAlloc(heap, 0, 65568) orelse return real_recv(s, buf, len, flags);
    defer _ = HeapFree(heap, 0, raw);
    const p: [*]u8 = @ptrCast(raw);
    const n = real_recv(s, p, 65536, 0);
    if (n < 0) return n;
    var payload = p[0..@intCast(n)];
    if (parseDatagramHeader(payload)) |hdr| payload = payload[hdr.consumed..];
    return @intCast(copyToBufsSingle(buf.?, @intCast(len), payload));
}

fn hook_getaddrinfo(node: ?[*:0]const u8, service: ?[*:0]const u8, hints_in: ?*const addrinfo, res: ?*?*addrinfo) callconv(.winapi) c_int {
    var hcopy: addrinfo = undefined;
    var hints: ?*const addrinfo = hints_in;
    if (cfg_enabled and hints != null) {
        hcopy = hints.?.*;
        if (hcopy.family == AF_INET6) hcopy.family = 0;
        hints = &hcopy;
    }
    const rc = real_getaddrinfo(node, service, hints, res);
    if (rc == 0 and res != null and res.?.* != null and cfg_enabled) {
        filterV4(res.?);
    }
    if (node != null) {
        logf("resolve {s}", .{std.mem.span(node.?)});
    }
    if (rc == 0 and node != null and res != null and res.?.* != null) {
        const name = std.mem.span(node.?);
        var it = res.?.*;
        var guard: usize = 0;
        while (it != null and guard < 16) : (guard += 1) {
            const ai = it.?;
            if (ai.addr) |a| {
                const b: [*]const u8 = @ptrCast(a);
                if (a.family == AF_INET) rememberName(b + 4, 4, name) else if (a.family == AF_INET6) rememberName(b + 8, 6, name);
            }
            it = ai.next;
        }
    }
    return rc;
}

fn utf16ToUtf8(src: [*:0]const u16, out: []u8) []const u8 {
    var i: usize = 0;
    var n: usize = 0;
    while (src[i] != 0 and n + 4 < out.len) : (i += 1) {
        const c = src[i];
        if (c < 0x80) {
            out[n] = @intCast(c);
            n += 1;
        } else if (c < 0x800) {
            out[n] = @intCast(0xC0 | (c >> 6));
            out[n + 1] = @intCast(0x80 | (c & 0x3F));
            n += 2;
        } else {
            out[n] = @intCast(0xE0 | (c >> 12));
            out[n + 1] = @intCast(0x80 | ((c >> 6) & 0x3F));
            out[n + 2] = @intCast(0x80 | (c & 0x3F));
            n += 3;
        }
    }
    return out[0..n];
}

fn hook_getaddrinfow(node: ?[*:0]const u16, service: ?[*:0]const u16, hints_in: ?*const addrinfo, res: ?*?*addrinfo) callconv(.winapi) c_int {
    var hcopy: addrinfo = undefined;
    var hints: ?*const addrinfo = hints_in;
    if (cfg_enabled and hints != null) {
        hcopy = hints.?.*;
        if (hcopy.family == AF_INET6) hcopy.family = 0;
        hints = &hcopy;
    }
    const rc = real_getaddrinfow(node, service, hints, res);
    if (rc == 0 and res != null and res.?.* != null and cfg_enabled) {
        filterV4(res.?);
    }
    if (node != null) {
        var lb: [512]u8 = undefined;
        logf("resolveW {s}", .{utf16ToUtf8(node.?, &lb)});
    }
    if (rc == 0 and node != null and res != null and res.?.* != null) {
        var nb: [512]u8 = undefined;
        const name = utf16ToUtf8(node.?, &nb);
        if (name.len > 0) {
            var it = res.?.*;
            var guard: usize = 0;
            while (it != null and guard < 16) : (guard += 1) {
                const ai = it.?;
                if (ai.addr) |a| {
                    const b: [*]const u8 = @ptrCast(a);
                    if (a.family == AF_INET) rememberName(b + 4, 4, name) else if (a.family == AF_INET6) rememberName(b + 8, 6, name);
                }
                it = ai.next;
            }
        }
    }
    return rc;
}

fn hook_closesocket(s: SOCKET) callconv(.winapi) c_int {
    udpDrop(s);
    forgetIocp(s);
    return extern_closesocket(s);
}

fn hook_gethostbyname(name: ?*anyopaque) callconv(.winapi) ?*anyopaque {
    return real_gethostbyname(name);
}

var ws_cache: [32]struct { h: usize, v: bool } = @splat(.{ .h = 0, .v = false });
var ws_cache_n: usize = 0;

fn containsNoCase(hay: []const u8, needle: []const u8) bool {
    if (needle.len > hay.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(hay[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn isWinsockModule(h: ?*anyopaque) bool {
    const hh = h orelse return false;
    const key = @intFromPtr(hh);
    var i: usize = 0;
    while (i < ws_cache_n) : (i += 1) {
        if (ws_cache[i].h == key) return ws_cache[i].v;
    }
    var buf: [300]u8 = @splat(0);
    const n = GetModuleFileNameA(hh, &buf, buf.len);
    var v = false;
    if (n > 0) {
        const lim = @min(@as(usize, n), buf.len);
        const nm = buf[0..lim];
        v = containsNoCase(nm, "ws2_32") or containsNoCase(nm, "mswsock");
    }
    if (ws_cache_n < ws_cache.len) {
        ws_cache[ws_cache_n] = .{ .h = key, .v = v };
        ws_cache_n += 1;
    }
    return v;
}

fn gpaReimpl(h: ?*anyopaque, name: [*:0]const u8) callconv(.winapi) ?*anyopaque {
    if (h == null) return null;
    ensureInit();
    ensureTables();
    if (isWinsockModule(h)) {
        if (lookupHook(name)) |p| return p;
    }
    var out: ?*anyopaque = null;
    const raw = @intFromPtr(name);
    if (raw < 0x10000) {
        if (LdrGetProcedureAddress(h, null, raw, &out) != 0) return null;
        return out;
    }
    const nm = std.mem.span(name);
    var ansi = ANSI_STRING{ .Length = @intCast(nm.len), .MaximumLength = @intCast(nm.len + 1), .Buffer = @constCast(name) };
    if (LdrGetProcedureAddress(h, &ansi, 0, &out) != 0) {
        if (verbose) logf("gpa miss {s}", .{nm});
        return null;
    }
    return out;
}

fn hook_getproc(h: ?*anyopaque, name: [*:0]const u8) callconv(.winapi) ?*anyopaque {
    return gpaReimpl(h, name);
}

fn hook_loadliba(name: [*:0]const u8) callconv(.winapi) ?*anyopaque {
    ensureInit();
    const r = real_loadliba(name);
    if (r != null) patchAllModules();
    return r;
}
fn hook_loadlibw(name: [*:0]const u16) callconv(.winapi) ?*anyopaque {
    ensureInit();
    const r = real_loadlibw(name);
    if (r != null) patchAllModules();
    return r;
}
fn hook_loadlibexa(name: [*:0]const u8, f: ?*anyopaque, flags: u32) callconv(.winapi) ?*anyopaque {
    ensureInit();
    const r = real_loadlibexa(name, f, flags);
    if (r != null) patchAllModules();
    return r;
}
fn hook_loadlibexw(name: [*:0]const u16, f: ?*anyopaque, flags: u32) callconv(.winapi) ?*anyopaque {
    ensureInit();
    const r = real_loadlibexw(name, f, flags);
    if (r != null) patchAllModules();
    return r;
}

fn hook_createiocp(f: ?*anyopaque, existing: ?*anyopaque, key: usize, threads: u32) callconv(.winapi) ?*anyopaque {
    ensureInit();
    const r = real_createiocp(f, existing, key, threads);
    if (r != null and f != null and @intFromPtr(f) != INVALID_HANDLE) {
        rememberIocp(@intFromPtr(f), r, key);
    }
    return r;
}

// ---------------------------------------------------------------------------
// hook tables and IAT patching
// ---------------------------------------------------------------------------
const HookDef = struct { name: []const u8, fnptr: usize };
var hooks_ws: [17]HookDef = undefined;
var hooks_ws_n: usize = 0;
var hooks_k32: [8]HookDef = undefined;
var hooks_k32_n: usize = 0;

fn ensureTables() void {
    if (hooks_ws_n != 0) return;
    hooks_ws[0] = .{ .name = "connect", .fnptr = @intFromPtr(&hook_connect) };
    hooks_ws[1] = .{ .name = "WSAConnect", .fnptr = @intFromPtr(&hook_wsaconnect) };
    hooks_ws[2] = .{ .name = "sendto", .fnptr = @intFromPtr(&hook_sendto) };
    hooks_ws[3] = .{ .name = "WSASendTo", .fnptr = @intFromPtr(&hook_wsasendto) };
    hooks_ws[4] = .{ .name = "recvfrom", .fnptr = @intFromPtr(&hook_recvfrom) };
    hooks_ws[5] = .{ .name = "WSARecvFrom", .fnptr = @intFromPtr(&hook_wsarecvfrom) };
    hooks_ws[6] = .{ .name = "send", .fnptr = @intFromPtr(&hook_send) };
    hooks_ws[7] = .{ .name = "WSASend", .fnptr = @intFromPtr(&hook_wsasend) };
    hooks_ws[8] = .{ .name = "recv", .fnptr = @intFromPtr(&hook_recv) };
    hooks_ws[9] = .{ .name = "WSARecv", .fnptr = @intFromPtr(&hook_wsarecv) };
    hooks_ws[10] = .{ .name = "getaddrinfo", .fnptr = @intFromPtr(&hook_getaddrinfo) };
    hooks_ws[11] = .{ .name = "GetAddrInfoW", .fnptr = @intFromPtr(&hook_getaddrinfow) };
    hooks_ws[12] = .{ .name = "closesocket", .fnptr = @intFromPtr(&hook_closesocket) };
    hooks_ws[13] = .{ .name = "gethostbyname", .fnptr = @intFromPtr(&hook_gethostbyname) };
    hooks_ws[14] = .{ .name = "ConnectEx", .fnptr = @intFromPtr(&hook_connectex) };
    hooks_ws[15] = .{ .name = "WSAConnectByNameW", .fnptr = @intFromPtr(&hook_wsaconnect) };
    hooks_ws[16] = .{ .name = "WSAIoctl", .fnptr = @intFromPtr(&hook_wsaioctl) };
    hooks_ws_n = 17;
    hooks_k32[0] = .{ .name = "GetProcAddress", .fnptr = @intFromPtr(&hook_getproc) };
    hooks_k32[1] = .{ .name = "LoadLibraryA", .fnptr = @intFromPtr(&hook_loadliba) };
    hooks_k32[2] = .{ .name = "LoadLibraryW", .fnptr = @intFromPtr(&hook_loadlibw) };
    hooks_k32[3] = .{ .name = "LoadLibraryExA", .fnptr = @intFromPtr(&hook_loadlibexa) };
    hooks_k32[4] = .{ .name = "LoadLibraryExW", .fnptr = @intFromPtr(&hook_loadlibexw) };
    hooks_k32[5] = .{ .name = "CreateIoCompletionPort", .fnptr = @intFromPtr(&hook_createiocp) };
    hooks_k32[6] = .{ .name = "GetQueuedCompletionStatus", .fnptr = @intFromPtr(&hook_gqcs) };
    hooks_k32[7] = .{ .name = "GetQueuedCompletionStatusEx", .fnptr = @intFromPtr(&hook_gqcsex) };
    hooks_k32_n = 8;
}

fn lookupHook(name: [*:0]const u8) ?*anyopaque {
    ensureTables();
    const s = std.mem.span(name);
    var i: usize = 0;
    while (i < hooks_ws_n) : (i += 1) {
        if (std.mem.eql(u8, hooks_ws[i].name, s)) return @ptrFromInt(hooks_ws[i].fnptr);
    }
    i = 0;
    while (i < hooks_k32_n) : (i += 1) {
        if (std.mem.eql(u8, hooks_k32[i].name, s)) return @ptrFromInt(hooks_k32[i].fnptr);
    }
    return null;
}

var patched_total: usize = 0;

fn patchThunk(slot: *usize, newval: usize) void {
    if (slot.* == newval) return;
    var old: u32 = 0;
    if (VirtualProtect(slot, @sizeOf(usize), 0x04, &old) == 0) return;
    slot.* = newval;
    var tmp: u32 = 0;
    _ = VirtualProtect(slot, @sizeOf(usize), old, &tmp);
    patched_total += 1;
}

fn eqNoCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn rvaOk(b: [*]const u8, nsec: u16, secs_off: usize, rva: u32) bool {
    var i: usize = 0;
    while (i < nsec) : (i += 1) {
        const so = secs_off + i * 40;
        const sva = @as(*align(1) const u32, @ptrCast(b + so + 12)).*;
        const svs = @as(*align(1) const u32, @ptrCast(b + so + 8)).*;
        const srs = @as(*align(1) const u32, @ptrCast(b + so + 16)).*;
        if (rva >= sva and rva < sva + @max(svs, srs)) return true;
    }
    return false;
}

fn patchModule(base: ?*anyopaque, modname: []const u8) void {
    const bb = base orelse return;
    // never patch another copy of ourselves (marker export): two copies hooking
    // each other's IAT would recurse forever on closesocket
    if (procFromModule(bb, "runproxiedMarker") != 0) {
        if (verbose) logf("skip own copy {s}", .{modname});
        return;
    }
    const b: [*]const u8 = @ptrCast(bb);
    if (b[0] != 'M' or b[1] != 'Z') return;
    const e_lfanew = @as(*align(1) const u32, @ptrCast(b + 0x3c)).*;
    const nt = b + e_lfanew;
    if (nt[0] != 'P' or nt[1] != 'E') return;
    const nsec = @as(*align(1) const u16, @ptrCast(nt + 6)).*;
    const optsz = @as(*align(1) const u16, @ptrCast(nt + 20)).*;
    const opt = nt + 24;
    const magic = @as(*align(1) const u16, @ptrCast(opt)).*;
    const dd = opt + (if (magic == 0x20b) @as(usize, 112) else 96);
    const imp_rva = @as(*align(1) const u32, @ptrCast(dd + 8)).*;
    if (imp_rva == 0) return;
    const secs_off: usize = e_lfanew + 24 + optsz;
    if (!rvaOk(b, nsec, secs_off, imp_rva)) return;
    const base_addr = @intFromPtr(bb);
    var d: [*]const u8 = @ptrFromInt(base_addr + imp_rva);
    var guard: usize = 0;
    while (guard < 256) : (guard += 1) {
        const desc: *align(1) const IMAGE_IMPORT_DESCRIPTOR = @ptrCast(d);
        if (desc.name == 0) break;
        if (!rvaOk(b, nsec, secs_off, desc.name)) {
            d += 20;
            continue;
        }
        const dll_ptr: [*:0]const u8 = @ptrFromInt(base_addr + desc.name);
        const dll = std.mem.span(dll_ptr);
        const is_k32 = eqNoCase(dll, "KERNEL32.dll") or eqNoCase(dll, "kernelbase.dll");
        const is_ws = eqNoCase(dll, "WS2_32.dll") or eqNoCase(dll, "mswsock.dll");
        if (is_k32 or is_ws) {
            const table = if (is_k32) hooks_k32[0..hooks_k32_n] else hooks_ws[0..hooks_ws_n];
            const oft: u32 = if (desc.original_first_thunk != 0) desc.original_first_thunk else desc.first_thunk;
            if (rvaOk(b, nsec, secs_off, oft) and rvaOk(b, nsec, secs_off, desc.first_thunk)) {
                var k: usize = 0;
                while (k < 4096) : (k += 1) {
                    const ent = @as(*align(1) const usize, @ptrFromInt(base_addr + oft + k * 8)).*;
                    if (ent == 0) break;
                    if ((ent >> 63) != 0) continue;
                    const nrva: u32 = @intCast(ent & 0x7fffffff);
                    if (!rvaOk(b, nsec, secs_off, nrva)) continue;
                    const nm_ptr: [*:0]const u8 = @ptrFromInt(base_addr + nrva);
                    const fname = std.mem.span(nm_ptr + 2);
                    for (table) |h| {
                        if (std.mem.eql(u8, h.name, fname)) {
                            const slot: *usize = @ptrFromInt(base_addr + desc.first_thunk + k * 8);
                            patchThunk(slot, h.fnptr);
                            if (verbose) logf("  hooked {s}!{s}", .{ modname, fname });
                            break;
                        }
                    }
                }
            }
        }
        d += 20;
    }
}

fn procFromModule(mod: ?*anyopaque, name: [*:0]const u8) usize {
    return procFromModuleDepth(mod, name, 0);
}

fn procFromModuleDepth(mod: ?*anyopaque, name: [*:0]const u8, depth: u32) usize {
    const mm = mod orelse return 0;
    const b: [*]const u8 = @ptrCast(mm);
    if (b[0] != 'M' or b[1] != 'Z') return 0;
    const e_lfanew = @as(*align(1) const u32, @ptrCast(b + 0x3c)).*;
    const nt = b + e_lfanew;
    if (nt[0] != 'P' or nt[1] != 'E') return 0;
    const nsec = @as(*align(1) const u16, @ptrCast(nt + 6)).*;
    const optsz = @as(*align(1) const u16, @ptrCast(nt + 20)).*;
    const opt = nt + 24;
    const magic = @as(*align(1) const u16, @ptrCast(opt)).*;
    const dd = opt + (if (magic == 0x20b) @as(usize, 112) else 96);
    const secs_off: usize = e_lfanew + 24 + optsz;
    const exp_rva = @as(*align(1) const u32, @ptrCast(dd)).*;
    const exp_sz = @as(*align(1) const u32, @ptrCast(dd + 4)).*;
    if (exp_rva == 0 or exp_sz == 0) return 0;
    if (!rvaOk(b, nsec, secs_off, exp_rva)) return 0;
    const base_addr = @intFromPtr(mm);
    const ed: [*]const u8 = @ptrFromInt(base_addr + exp_rva);
    const num_names = @as(*align(1) const u32, @ptrCast(ed + 24)).*;
    const names_rva = @as(*align(1) const u32, @ptrCast(ed + 32)).*;
    const ords_rva = @as(*align(1) const u32, @ptrCast(ed + 36)).*;
    const funcs_rva = @as(*align(1) const u32, @ptrCast(ed + 28)).*;
    if (!rvaOk(b, nsec, secs_off, names_rva)) return 0;
    if (!rvaOk(b, nsec, secs_off, ords_rva)) return 0;
    if (!rvaOk(b, nsec, secs_off, funcs_rva)) return 0;
    const want = std.mem.span(name);
    var i: usize = 0;
    while (i < num_names) : (i += 1) {
        const nm_rva = @as(*align(1) const u32, @ptrFromInt(base_addr + names_rva + i * 4)).*;
        if (!rvaOk(b, nsec, secs_off, nm_rva)) continue;
        const sp: [*:0]const u8 = @ptrFromInt(base_addr + nm_rva);
        if (std.mem.eql(u8, std.mem.span(sp), want)) {
            const ord = @as(*align(1) const u16, @ptrFromInt(base_addr + ords_rva + i * 2)).*;
            const frva = @as(*align(1) const u32, @ptrFromInt(base_addr + funcs_rva + @as(usize, ord) * 4)).*;
            if (frva >= exp_rva and frva < exp_rva + exp_sz) {
                if (depth > 2) return 0;
                const fs: [*:0]const u8 = @ptrFromInt(base_addr + frva);
                const fstr = std.mem.span(fs);
                const dot = std.mem.indexOfScalar(u8, fstr, '.') orelse return 0;
                var dllbuf: [128]u8 = @splat(0);
                const dn = fstr[0..dot];
                if (dn.len + 4 >= dllbuf.len) return 0;
                @memcpy(dllbuf[0..dn.len], dn);
                @memcpy(dllbuf[dn.len .. dn.len + 4], ".dll");
                const h2 = LoadLibraryA(@ptrCast(&dllbuf));
                if (h2 == null) return 0;
                return procFromModuleDepth(h2, @ptrCast(fs + dot + 1), depth + 1);
            }
            if (!rvaOk(b, nsec, secs_off, frva)) return 0;
            return base_addr + frva;
        }
    }
    return 0;
}

var self_base: ?*anyopaque = null;
var seen_mods: [512]usize = @splat(0);
var seen_n: usize = 0;
var seen_lock: usize = 0;

fn patchAllModules() void {
    AcquireSRWLockExclusive(&seen_lock);
    defer ReleaseSRWLockExclusive(&seen_lock);
    const snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == null or @intFromPtr(snap) == INVALID_HANDLE) return;
    defer _ = CloseHandle(snap);
    var me: MODULEENTRY32W = std.mem.zeroes(MODULEENTRY32W);
    me.dwSize = @sizeOf(MODULEENTRY32W);
    if (Module32FirstW(snap, &me) == 0) return;
    while (true) {
        var mbuf: [128]u8 = undefined;
        if (me.modBaseAddr) |b| {
            const key = @intFromPtr(b);
            var known = false;
            var i: usize = 0;
            while (i < seen_n) : (i += 1) {
                if (seen_mods[i] == key) {
                    known = true;
                    break;
                }
            }
            if (!known and b != self_base) {
                if (verbose) logf("patching {s} base=0x{x} self=0x{x}", .{ utf16ToUtf8(@ptrCast(&me.szModule), &mbuf), @intFromPtr(b), @intFromPtr(self_base) });
                patchModule(b, utf16ToUtf8(@ptrCast(&me.szModule), &mbuf));
                if (seen_n < seen_mods.len) {
                    seen_mods[seen_n] = key;
                    seen_n += 1;
                }
            }
        }
        if (Module32NextW(snap, &me) == 0) break;
    }
}

// ---------------------------------------------------------------------------
// inline hooks (needed because Go resolves kernel32 exports itself and caches
// ws2_32 function pointers, bypassing IAT patching)
// ---------------------------------------------------------------------------
var hws2: ?*anyopaque = null;
var inline_done: bool = false;

fn writeJmpAt(src: usize, dst: usize) bool {
    const delta: i64 = @as(i64, @intCast(dst)) - @as(i64, @intCast(src + 5));
    if (delta < -2147483648 or delta > 2147483647) return false;
    const q: [*]u8 = @ptrFromInt(src);
    q[0] = 0xE9;
    const r: i32 = @intCast(delta);
    @memcpy(q[1..5], @as([*]const u8, @ptrCast(&r))[0..4]);
    return true;
}

fn writeAbsJmpAt(src: usize, dst: usize) void {
    const q: [*]u8 = @ptrFromInt(src);
    q[0] = 0x48;
    q[1] = 0xB8; // mov rax, imm64
    const dv: u64 = @intCast(dst);
    @memcpy(q[2..10], @as([*]const u8, @ptrCast(&dv))[0..8]);
    q[10] = 0xFF;
    q[11] = 0xE0; // jmp rax
}

fn allocNear(target: usize) ?usize {
    const gran: usize = 0x10000;
    const base = target & ~(gran - 1);
    var delta: usize = gran;
    while (delta < 0x60000000) : (delta += gran) {
        if (base > delta) {
            const a = base - delta;
            if (VirtualAlloc(@ptrFromInt(a), gran, 0x3000, 0x40)) |m| return @intFromPtr(m);
        }
        const b = base + delta;
        if (VirtualAlloc(@ptrFromInt(b), gran, 0x3000, 0x40)) |m| return @intFromPtr(m);
    }
    return null;
}

fn rdU32(p: [*]const u8) u32 {
    var v: u32 = undefined;
    @memcpy(@as([*]u8, @ptrCast(&v))[0..4], p[0..4]);
    return v;
}

fn inlineHookTarget(target: usize, detour: usize) ?usize {
    var total: usize = 0;
    while (total < 5) {
        var hs: [64]u8 = @splat(0);
        const n = hde64_disasm(@ptrFromInt(target + total), &hs);
        if (n == 0 or n > 15) return null;
        const flags = rdU32(@as([*]const u8, @ptrCast(&hs)) + 33);
        if ((flags & 0x200) != 0) return null;
        total += n;
        if (total > 16) return null;
    }
    const mem = VirtualAlloc(null, 4096, 0x3000, 0x40) orelse return null;
    const tramp = @intFromPtr(mem);
    const src: [*]const u8 = @ptrFromInt(target);
    const dst: [*]u8 = @ptrFromInt(tramp);
    @memcpy(dst[0..total], src[0..total]);
    writeAbsJmpAt(tramp + total, target + total);

    const island = allocNear(target) orelse return null;
    writeAbsJmpAt(island, detour);

    var old: u32 = 0;
    if (VirtualProtect(@ptrFromInt(target), total, 0x40, &old) == 0) return null;
    const ok = writeJmpAt(target, island);
    if (ok) {
        const q: [*]u8 = @ptrFromInt(target);
        var i: usize = 5;
        while (i < total) : (i += 1) q[i] = 0xCC;
    }
    var tmp: u32 = 0;
    _ = VirtualProtect(@ptrFromInt(target), total, old, &tmp);
    _ = FlushInstructionCache(@ptrFromInt(INVALID_HANDLE), @ptrFromInt(target), total);
    if (!ok) return null;
    return tramp;
}

fn installOne(name: [*:0]const u8, detour: usize) ?usize {
    const addr = procFromModule(hws2, name);
    if (addr == 0) return null;
    const t = inlineHookTarget(addr, detour) orelse {
        logf("inline hook FAILED {s}", .{std.mem.span(name)});
        return null;
    };
    logf("inline hook {s} ok", .{std.mem.span(name)});
    return t;
}

fn installWs2Inline() void {
    if (inline_done) return;
    inline_done = true;
    if (hws2 == null) return;
    if (installOne("connect", @intFromPtr(&hook_connect))) |t| real_connect = @ptrFromInt(t);
    if (installOne("WSAConnect", @intFromPtr(&hook_wsaconnect))) |t| real_wsaconnect = @ptrFromInt(t);
    if (installOne("sendto", @intFromPtr(&hook_sendto))) |t| real_sendto = @ptrFromInt(t);
    if (installOne("WSASendTo", @intFromPtr(&hook_wsasendto))) |t| real_wsasendto = @ptrFromInt(t);
    if (installOne("recvfrom", @intFromPtr(&hook_recvfrom))) |t| real_recvfrom = @ptrFromInt(t);
    if (installOne("WSARecvFrom", @intFromPtr(&hook_wsarecvfrom))) |t| real_wsarecvfrom = @ptrFromInt(t);
    if (installOne("send", @intFromPtr(&hook_send))) |t| real_send = @ptrFromInt(t);
    if (installOne("WSASend", @intFromPtr(&hook_wsasend))) |t| real_wsasend = @ptrFromInt(t);
    if (installOne("recv", @intFromPtr(&hook_recv))) |t| real_recv = @ptrFromInt(t);
    if (installOne("WSARecv", @intFromPtr(&hook_wsarecv))) |t| real_wsarecv = @ptrFromInt(t);
    if (installOne("getaddrinfo", @intFromPtr(&hook_getaddrinfo))) |t| real_getaddrinfo = @ptrFromInt(t);
    if (installOne("GetAddrInfoW", @intFromPtr(&hook_getaddrinfow))) |t| real_getaddrinfow = @ptrFromInt(t);
    if (installOne("closesocket", @intFromPtr(&hook_closesocket))) |t| real_closesocket = @ptrFromInt(t);
    if (installOne("socket", @intFromPtr(&hook_socket))) |t| real_socket = @ptrFromInt(t);
    logRaw("inline hooks installed");
}

fn hook_socket(af: c_int, t: c_int, p: c_int) callconv(.winapi) SOCKET {
    const r = real_socket(af, t, p);
    if (verbose) logf("socket(af={d},type={d}) -> {d}", .{ af, t, r });
    return r;
}

var gpa_done: bool = false;
var patched_targets: [16]usize = @splat(0);
var patched_targets_n: usize = 0;

fn installNoOrig(target: usize, detour: usize) bool {
    var i: usize = 0;
    while (i < patched_targets_n) : (i += 1) {
        if (patched_targets[i] == target) return true;
    }
    const island = allocNear(target) orelse return false;
    writeAbsJmpAt(island, detour);
    const ib: [*]const u8 = @ptrFromInt(island);
    logf("island 0x{x} bytes {x:0>2} {x:0>2} {x:0>2}..{x:0>2} dst=0x{x}", .{ island, ib[0], ib[1], ib[10], ib[11], detour });
    var old: u32 = 0;
    if (VirtualProtect(@ptrFromInt(target), 5, 0x40, &old) == 0) return false;
    const ok = writeJmpAt(target, island);
    var tmp: u32 = 0;
    _ = VirtualProtect(@ptrFromInt(target), 5, old, &tmp);
    _ = FlushInstructionCache(@ptrFromInt(INVALID_HANDLE), @ptrFromInt(target), 5);
    if (!ok) return false;
    if (patched_targets_n < patched_targets.len) {
        patched_targets[patched_targets_n] = target;
        patched_targets_n += 1;
    }
    return true;
}

fn installGpaInline() void {
    if (gpa_done) return;
    gpa_done = true;
    const kb = GetModuleHandleA("kernelbase.dll");
    const k32 = GetModuleHandleA("kernel32.dll");
    var done = false;
    const a1 = procFromModule(kb, "GetProcAddress");
    if (a1 != 0 and installNoOrig(a1, @intFromPtr(&gpaReimpl))) {
        logf("gpa inline hook kernelbase=0x{x}", .{a1});
        done = true;
    }
    const a2 = procFromModule(k32, "GetProcAddress");
    if (a2 != 0 and a2 != a1 and installNoOrig(a2, @intFromPtr(&gpaReimpl))) {
        logf("gpa inline hook kernel32=0x{x}", .{a2});
        done = true;
    }
    if (!done) logRaw("gpa inline hook FAILED");
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------
var init_state: u32 = 0;
var init_lock: usize = 0;

fn resolveSome(mods: []const ?*anyopaque, name: [*:0]const u8) ?usize {
    for (mods) |m| {
        const p = procFromModule(m, name);
        if (p != 0) return p;
    }
    return null;
}

fn initNow() void {
    logInit();
    ensureTables();
    if (!cfg_ready) cfgInit();
    var self: ?*anyopaque = null;
    _ = GetModuleHandleExW(4, @ptrCast(&DllMain), &self);
    self_base = self;

    const k32 = GetModuleHandleA("kernel32.dll");
    const kbase = GetModuleHandleA("kernelbase.dll");
    const mods = [_]?*anyopaque{ kbase, k32 };

    if (resolveSome(&mods, "GetProcAddress")) |p| real_getproc = @ptrFromInt(p);
    if (resolveSome(&mods, "LoadLibraryA")) |p| real_loadliba = @ptrFromInt(p);
    if (resolveSome(&mods, "LoadLibraryW")) |p| real_loadlibw = @ptrFromInt(p);
    if (resolveSome(&mods, "LoadLibraryExA")) |p| real_loadlibexa = @ptrFromInt(p);
    if (resolveSome(&mods, "LoadLibraryExW")) |p| real_loadlibexw = @ptrFromInt(p);
    if (resolveSome(&mods, "CreateIoCompletionPort")) |p| real_createiocp = @ptrFromInt(p);
    if (resolveSome(&mods, "GetQueuedCompletionStatus")) |p| real_gqcs = @ptrFromInt(p);
    if (resolveSome(&mods, "GetQueuedCompletionStatusEx")) |p| real_gqcsex = @ptrFromInt(p);

    const hws = LoadLibraryA("ws2_32.dll");
    if (hws == null) {
        logRaw("ws2_32.dll load failed");
        return;
    }
    hws2 = hws;
    const ws = [_]?*anyopaque{hws};
    if (resolveSome(&ws, "connect")) |p| real_connect = @ptrFromInt(p);
    if (resolveSome(&ws, "WSAConnect")) |p| real_wsaconnect = @ptrFromInt(p);
    if (resolveSome(&ws, "sendto")) |p| real_sendto = @ptrFromInt(p);
    if (resolveSome(&ws, "WSASendTo")) |p| real_wsasendto = @ptrFromInt(p);
    if (resolveSome(&ws, "recvfrom")) |p| real_recvfrom = @ptrFromInt(p);
    if (resolveSome(&ws, "WSARecvFrom")) |p| real_wsarecvfrom = @ptrFromInt(p);
    if (resolveSome(&ws, "send")) |p| real_send = @ptrFromInt(p);
    if (resolveSome(&ws, "WSASend")) |p| real_wsasend = @ptrFromInt(p);
    if (resolveSome(&ws, "recv")) |p| real_recv = @ptrFromInt(p);
    if (resolveSome(&ws, "WSARecv")) |p| real_wsarecv = @ptrFromInt(p);
    if (resolveSome(&ws, "getaddrinfo")) |p| real_getaddrinfo = @ptrFromInt(p);
    if (resolveSome(&ws, "freeaddrinfo")) |p| real_freeaddrinfo = @ptrFromInt(p);
    if (resolveSome(&ws, "GetAddrInfoW")) |p| real_getaddrinfow = @ptrFromInt(p);
    if (resolveSome(&ws, "FreeAddrInfoW")) |p| real_freeaddrinfow = @ptrFromInt(p);
    if (resolveSome(&ws, "closesocket")) |p| real_closesocket = @ptrFromInt(p);
    if (resolveSome(&ws, "gethostbyname")) |p| real_gethostbyname = @ptrFromInt(p);
    if (resolveSome(&ws, "WSAIoctl")) |p| real_wsaioctl = @ptrFromInt(p);
    const hms = LoadLibraryA("mswsock.dll");
    if (hms != null) {
        const cxp = procFromModule(hms, "ConnectEx");
        if (cxp != 0) real_connectex = @ptrFromInt(cxp);
    }

    installGpaInline();
    patchAllModules();
    logf("init done pid={d} patched={d} modules={d}", .{ GetCurrentProcessId(), patched_total, seen_n });
}

var init_tid: u32 = 0;

fn ensureInit() void {
    if (@atomicLoad(u32, &init_state, .seq_cst) == 3) return;
    // reentrancy guard: during init this thread loads DLLs whose loaders call
    // GetProcAddress; our inline hook must not block on the lock we already hold
    if (init_tid != 0 and init_tid == GetCurrentThreadId()) return;
    AcquireSRWLockExclusive(&init_lock);
    defer ReleaseSRWLockExclusive(&init_lock);
    if (init_state == 3) return;
    init_tid = GetCurrentThreadId();
    init_state = 2;
    initNow();
    init_tid = 0;
    init_state = 3;
}

fn initThread(_: ?*anyopaque) callconv(.winapi) u32 {
    ensureInit();
    return 0;
}

// ---------------------------------------------------------------------------
// exports
// ---------------------------------------------------------------------------
pub export fn SymFromAddr(hProcess: ?*anyopaque, Address: u64, displacement: ?*u64, symbol: ?*anyopaque) callconv(.winapi) i32 {
    _ = hProcess;
    _ = Address;
    _ = displacement;
    _ = symbol;
    return 0;
}
pub export fn SymFromAddrW(hProcess: ?*anyopaque, Address: u64, displacement: ?*u64, symbol: ?*anyopaque) callconv(.winapi) i32 {
    _ = hProcess;
    _ = Address;
    _ = displacement;
    _ = symbol;
    return 0;
}
pub export fn SymInitialize(hProcess: ?*anyopaque, path: ?*anyopaque, invade: i32) callconv(.winapi) i32 {
    _ = hProcess;
    _ = path;
    _ = invade;
    return 1;
}
pub export fn SymCleanup(hProcess: ?*anyopaque) callconv(.winapi) i32 {
    _ = hProcess;
    return 1;
}
pub export fn SymSetOptions(opts: u32) callconv(.winapi) u32 {
    return opts;
}
pub export fn SymGetOptions() callconv(.winapi) u32 {
    return 0;
}
pub export fn SymLoadModuleExW(a: ?*anyopaque, b: ?*anyopaque, c: ?*anyopaque, d: ?*anyopaque, e: u32, f: u32, g: ?*anyopaque, h: u32) callconv(.winapi) u64 {
    _ = a;
    _ = b;
    _ = c;
    _ = d;
    _ = e;
    _ = f;
    _ = g;
    _ = h;
    return 0;
}
pub export fn SymUnloadModule64(hProcess: ?*anyopaque, base: u64) callconv(.winapi) i32 {
    _ = hProcess;
    _ = base;
    return 1;
}

pub export fn runproxiedMarker() callconv(.winapi) usize {
    return 0x61677970726F7879;
}

pub export fn DllMain(hinst: ?*anyopaque, reason: u32, reserved: ?*anyopaque) callconv(.winapi) i32 {
    _ = reserved;
    if (reason == 1) {
        _ = DisableThreadLibraryCalls(hinst);
        logInit();
        logf("agyproxy attached pid={d}", .{GetCurrentProcessId()});
        // patch the host image synchronously: this runs before any host code,
        // so cached GetProcAddress results can never bypass the hooks
        ensureTables();
        var self: ?*anyopaque = null;
        _ = GetModuleHandleExW(4, @ptrCast(&DllMain), &self);
        self_base = self;
        const exe = GetModuleHandleA(null);
        installGpaInline();
        const before = patched_total;
        patchModule(exe, "host");
        logf("early patch host thunks={d}", .{patched_total - before});
        _ = CreateThread(null, 0, initThread, null, 0, null);
    }
    return 1;
}
