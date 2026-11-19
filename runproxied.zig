// runproxied: universal launcher. Starts any exe with our SOCKS5 hook DLL injected.
// Usage: runproxied.exe [--proxy socks5h://user:pass@host:port] -- target.exe [args...]
const std = @import("std");

const BOOL = i32;
const DWORD = u32;
const HANDLE = ?*anyopaque;
const SIZE_T = usize;
const LPSTR = [*:0]u8;

const STARTUPINFOW = extern struct {
    cb: DWORD,
    lpReserved: ?[*:0]u16,
    lpDesktop: ?[*:0]u16,
    lpTitle: ?[*:0]u16,
    dwX: DWORD,
    dwY: DWORD,
    dwXSize: DWORD,
    dwYSize: DWORD,
    dwXCountChars: DWORD,
    dwYCountChars: DWORD,
    dwFillAttribute: DWORD,
    dwFlags: DWORD,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: ?[*]u8,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
};

const PROCESS_INFORMATION = extern struct {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
};

extern "kernel32" fn CreateProcessW(app: ?[*:0]u16, cmd: ?[*:0]u16, pa: ?*anyopaque, ta: ?*anyopaque, inherit: BOOL, flags: DWORD, env: ?*anyopaque, dir: ?[*:0]u16, si: *STARTUPINFOW, pi: *PROCESS_INFORMATION) callconv(.winapi) BOOL;
extern "kernel32" fn VirtualAllocEx(h: HANDLE, addr: ?*anyopaque, size: SIZE_T, typ: DWORD, prot: DWORD) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn WriteProcessMemory(h: HANDLE, base: ?*anyopaque, buf: *const anyopaque, size: SIZE_T, written: ?*SIZE_T) callconv(.winapi) BOOL;
extern "kernel32" fn CreateRemoteThread(h: HANDLE, attr: ?*anyopaque, stack: SIZE_T, start: *const anyopaque, param: ?*anyopaque, flags: DWORD, id: ?*DWORD) callconv(.winapi) HANDLE;
extern "kernel32" fn WaitForSingleObject(h: HANDLE, ms: DWORD) callconv(.winapi) DWORD;
extern "kernel32" fn ResumeThread(h: HANDLE) callconv(.winapi) DWORD;
extern "kernel32" fn CloseHandle(h: HANDLE) callconv(.winapi) BOOL;
extern "kernel32" fn GetModuleHandleA(n: ?[*:0]const u8) callconv(.winapi) HANDLE;
extern "kernel32" fn GetProcAddress(h: HANDLE, n: [*:0]const u8) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetLastError() callconv(.winapi) DWORD;
extern "kernel32" fn GetFullPathNameA(n: [*:0]const u8, len: DWORD, buf: [*]u8, part: ?*?[*:0]u8) callconv(.winapi) DWORD;
extern "kernel32" fn WaitForSingleObjectEx(h: HANDLE, ms: DWORD, alertable: BOOL) callconv(.winapi) DWORD;

extern "kernel32" fn GetCommandLineW() callconv(.winapi) [*:0]u16;
extern "kernel32" fn LocalFree(h: ?*anyopaque) callconv(.winapi) ?*anyopaque;
extern "shell32" fn CommandLineToArgvW(cmd: [*:0]const u16, argc: *c_int) callconv(.winapi) ?[*]?[*:0]u16;

const CREATE_SUSPENDED: DWORD = 0x4;
const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const MEM_RELEASE: DWORD = 0x8000;
const PAGE_READWRITE: DWORD = 0x4;
const INFINITE: DWORD = 0xFFFFFFFF;
const STILL_ACTIVE: DWORD = 259;

fn die(msg: []const u8) noreturn {
    std.debug.print("runproxied: {s}\n", .{msg});
    std.process.exit(1);
}

fn utf8ToUtf16Alloc(a: std.mem.Allocator, s: []const u8) ![:0]u16 {
    return std.unicode.utf8ToUtf16LeAllocZ(a, s);
}

fn utf16ToUtf8Buf(w: []const u16, out: []u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < w.len) {
        const c0 = w[i];
        i += 1;
        if (c0 < 0x80) {
            if (n + 1 > out.len) break;
            out[n] = @intCast(c0);
            n += 1;
        } else if (c0 < 0x800) {
            if (n + 2 > out.len) break;
            out[n] = @intCast(0xC0 | (c0 >> 6));
            out[n + 1] = @intCast(0x80 | (c0 & 0x3F));
            n += 2;
        } else {
            if (n + 3 > out.len) break;
            out[n] = @intCast(0xE0 | (c0 >> 12));
            out[n + 1] = @intCast(0x80 | ((c0 >> 6) & 0x3F));
            out[n + 2] = @intCast(0x80 | (c0 & 0x3F));
            n += 3;
        }
    }
    return n;
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var args_buf: [64][1024]u8 = undefined;
    var args_lens: [64]usize = undefined;
    var args_n: usize = 0;
    {
        // read args via CommandLineToArgvW (version-independent, no std.process API drift)
        var argc: c_int = 0;
        const argv = CommandLineToArgvW(GetCommandLineW(), &argc) orelse die("args");
        defer _ = LocalFree(@ptrCast(argv));
        var k: usize = 0;
        while (k < @as(usize, @intCast(argc)) and args_n < args_buf.len) : (k += 1) {
            const w: [*:0]const u16 = @ptrCast(argv[k]);
            var wlen: usize = 0;
            while (w[wlen] != 0) wlen += 1;
            const n = utf16ToUtf8Buf(w[0..wlen], &args_buf[args_n]);
            args_lens[args_n] = n;
            args_n += 1;
        }
    }
    const args = args_buf;

    // parse args: [--proxy URL] [--dll path] -- target [args...]
    var proxy: ?[]const u8 = null;
    var dll_path: ?[]const u8 = null;
    var quiet = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i][0..args_lens[i]];
        if (std.mem.eql(u8, a, "--proxy")) {
            i += 1;
            if (i >= args.len) die("--proxy needs a value");
            proxy = args[i][0..args_lens[i]];
        } else if (std.mem.eql(u8, a, "--dll")) {
            i += 1;
            if (i >= args.len) die("--dll needs a value");
            dll_path = args[i][0..args_lens[i]];
        } else if (std.mem.eql(u8, a, "--quiet") or std.mem.eql(u8, a, "-q")) {
            quiet = true;
        } else if (std.mem.eql(u8, a, "--")) {
            i += 1;
            break;
        } else {
            break;
        }
    }
    if (i >= args.len) {
        std.debug.print("usage: runproxied.exe [--proxy socks5h://user:pass@host:port] [--dll runproxied.dll] [--quiet] -- target.exe [args...]\n", .{});
        std.debug.print("default dll: runproxied.dll next to runproxied.exe; proxy: --proxy or built-in default\n", .{});
        return;
    }

    // dll path: --dll or agyproxy.dll next to this exe
    var dll_buf: [1024]u8 = undefined;
    var dll_z: [*:0]const u8 = undefined;
    if (dll_path) |dp| {
        if (dp.len >= dll_buf.len) die("dll path too long");
        @memcpy(dll_buf[0..dp.len], dp);
        dll_buf[dp.len] = 0;
        dll_z = @ptrCast(&dll_buf);
    } else {
        // find our own exe dir
        var self_buf: [1024]u8 = undefined;
        const self_n = GetModuleFileNameA_impl(&self_buf);
        var dir_end: usize = self_n;
        while (dir_end > 0 and self_buf[dir_end - 1] != '\\') dir_end -= 1;
        const name = "runproxied.dll";
        if (dir_end + name.len >= dll_buf.len) die("path too long");
        @memcpy(dll_buf[0..dir_end], self_buf[0..dir_end]);
        @memcpy(dll_buf[dir_end .. dir_end + name.len], name);
        dll_buf[dir_end + name.len] = 0;
        dll_z = @ptrCast(&dll_buf);
    }

    // build command line: target + args, properly quoted
    var cl_buf: [4096]u8 = undefined;
    var cl_len: usize = 0;
    var ai: usize = i;
    while (ai < args_n) : (ai += 1) {
        const a = args[ai][0..args_lens[ai]];
        if (cl_len > 0) {
            cl_buf[cl_len] = ' ';
            cl_len += 1;
        }
        const needs_quote = std.mem.indexOfScalar(u8, a, ' ') != null or a.len == 0;
        if (needs_quote) {
            cl_buf[cl_len] = '"';
            cl_len += 1;
        }
        if (cl_len + a.len >= cl_buf.len) die("command line too long");
        @memcpy(cl_buf[cl_len .. cl_len + a.len], a);
        cl_len += a.len;
        if (needs_quote) {
            cl_buf[cl_len] = '"';
            cl_len += 1;
        }
    }
    if (cl_len >= cl_buf.len) die("command line too long");
    cl_buf[cl_len] = 0;

    // set AGY_PROXY in our environment before CreateProcess (child inherits)
    if (quiet) {
        _ = SetEnvironmentVariableA("AGYPROXY_QUIET", "1");
    }
    if (proxy) |p| {
        var env_buf: [1024]u8 = undefined;
        if (p.len + 10 >= env_buf.len) die("proxy url too long");
        @memcpy(env_buf[0..9], "AGY_PROXY");
        env_buf[9] = '=';
        @memcpy(env_buf[10 .. 10 + p.len], p);
        env_buf[10 + p.len] = 0;
        _ = c_putenv(@ptrCast(&env_buf));
    }

    // wide command line
    const cl_w = try utf8ToUtf16Alloc(gpa, cl_buf[0..cl_len]);
    defer gpa.free(cl_w);

    var si = std.mem.zeroes(STARTUPINFOW);
    si.cb = @sizeOf(STARTUPINFOW);
    var pi = std.mem.zeroes(PROCESS_INFORMATION);

    const ok = CreateProcessW(null, cl_w.ptr, null, null, 0, CREATE_SUSPENDED, null, null, &si, &pi);
    if (ok == 0) {
        std.debug.print("runproxied: CreateProcess failed err={d} cmd={s}\n", .{ GetLastError(), cl_buf[0..cl_len] });
        std.process.exit(1);
    }
    defer _ = CloseHandle(pi.hProcess);
    defer _ = CloseHandle(pi.hThread);

    // classic injection: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryA)
    const dll_len = std.mem.len(dll_z) + 1;
    const remote = VirtualAllocEx(pi.hProcess, null, dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) orelse {
        _ = ResumeThread(pi.hThread);
        die("VirtualAllocEx failed");
    };
    _ = WriteProcessMemory(pi.hProcess, remote, @ptrCast(dll_z), dll_len, null);

    const k32 = GetModuleHandleA("kernel32.dll");
    const loadlib = GetProcAddress(k32, "LoadLibraryA") orelse die("no LoadLibraryA");
    const t = CreateRemoteThread(pi.hProcess, null, 0, @ptrCast(loadlib), remote, 0, null) orelse {
        _ = ResumeThread(pi.hThread);
        die("CreateRemoteThread failed");
    };
    _ = WaitForSingleObject(t, 10000);
    _ = CloseHandle(t);

    _ = ResumeThread(pi.hThread);

    // wait for the child and forward its exit code
    _ = WaitForSingleObject(pi.hProcess, INFINITE);
    var code: DWORD = 0;
    _ = GetExitCodeProcess_impl(pi.hProcess, &code);
    std.process.exit(@intCast(code & 0xff));
}

extern "kernel32" fn SetEnvironmentVariableA(name: [*:0]const u8, value: [*:0]const u8) callconv(.winapi) BOOL;
fn c_putenv(kv: [*:0]const u8) c_int {
    // kv is "AGY_PROXY=..." ; split at '='
    const s = std.mem.span(kv);
    const eq = std.mem.indexOfScalar(u8, s, '=') orelse return -1;
    var name_buf: [64]u8 = undefined;
    if (eq >= name_buf.len) return -1;
    @memcpy(name_buf[0..eq], s[0..eq]);
    name_buf[eq] = 0;
    const val: [*:0]const u8 = @ptrCast(kv + eq + 1);
    return if (SetEnvironmentVariableA(@ptrCast(&name_buf), val) != 0) 0 else -1;
}

extern "kernel32" fn GetModuleFileNameA(h: HANDLE, buf: [*]u8, n: DWORD) callconv(.winapi) DWORD;
fn GetModuleFileNameA_impl(buf: [*]u8) usize {
    return @intCast(GetModuleFileNameA(null, buf, 1024));
}

extern "kernel32" fn GetExitCodeProcess(h: HANDLE, code: *DWORD) callconv(.winapi) BOOL;
fn GetExitCodeProcess_impl(h: HANDLE, code: *DWORD) BOOL {
    return GetExitCodeProcess(h, code);
}
