# runproxied

Route **all** TCP and UDP network traffic of any Windows x64 executable through a SOCKS5 proxy (with remote DNS, i.e. `socks5h` behavior) — no environment variables like `HTTP_PROXY` needed by the target program, no proxy support required inside the program itself.

## How it works

- `runproxied.exe` — a launcher. It starts any executable suspended, injects `runproxied.dll` into it, then resumes it.
- `runproxied.dll` — the hook core. Once inside the process it:
  - intercepts every Winsock entry point: `connect`, `WSAConnect`, `ConnectEx` (via `WSAIoctl`), `send`, `sendto`, `WSASend`, `WSASendTo`, `recv`, `recvfrom`, `WSARecv`, `WSARecvFrom`, `closesocket`, `socket`
  - intercepts `GetProcAddress`/`LdrGetProcedureAddress` both via IAT patching and inline hooking, so programs that resolve Winsock dynamically (Go binaries, for example) are covered too
  - tunnels all TCP connections through a local relay thread that speaks SOCKS5 to the configured proxy
  - wraps all UDP datagrams in SOCKS5 UDP ASSOCIATE envelopes and unwraps the replies
  - sends hostnames to the proxy (ATYP=domain), so DNS resolution happens on the proxy side — true `socks5h` semantics
  - blocks IPv6 (AAAA answers are filtered) so nothing leaks outside the IPv4 proxy path

Loopback connections (127.x, ::1) are never redirected, so local IPC keeps working.

## Usage

```
runproxied.exe [--proxy socks5h://user:pass@host:port] [--dll runproxied.dll] [--quiet] -- target.exe [args...]
```

- `--proxy` — SOCKS5 URL. Also accepts `socks5://`. If omitted, the `AGY_PROXY` environment variable is used; if that is unset too, no proxying happens.
- `--dll` — path to `runproxied.dll` (default: next to `runproxied.exe`).
- `--quiet` / `-q` — disable the log file entirely.
- `--` — everything after this is the target command line.

Examples:

```
runproxied.exe --proxy socks5h://user:pass@127.0.0.1:1080 -- curl.exe -v https://example.com
runproxied.exe -q -- someapp.exe --arg value
```

Environment variables (usually set automatically by the launcher):

- `AGY_PROXY` — proxy URL (same syntax as `--proxy`); set it to `none` to disable proxying.
- `AGYPROXY_VERBOSE=1` — verbose log.
- `AGYPROXY_QUIET=1` — no log file.

Without `--quiet`, a diagnostic log is written next to the target executable as `<exename>.runproxied.log` (each proxied program gets its own file; if the directory is not writable, it falls back to `%TEMP%\runproxied-<pid>.log`).

## Building

Requires [Zig](https://ziglang.org/) (built with 0.17-dev) and the Hacker Disassembler Engine 64 sources for instruction-length decoding used by the inline hooks:

```
hde/hde64.c
hde/hde64.h
hde/table64.h
hde/pstdint.h
```

(from https://github.com/TsudaKageyu/minhook/tree/master/src/hde)

Build:

```
zig build-lib runproxied_hook.zig hde/hde64.c -I hde -dynamic -target x86_64-windows-gnu -lc -femit-bin=runproxied.dll
zig build-exe runproxied.zig -target x86_64-windows-gnu -femit-bin=runproxied.exe
```

Put `runproxied.exe` and `runproxied.dll` next to each other.

## Limitations

- Windows x64 only.
- IPv6 traffic to external hosts is blocked (by design — everything must go through the IPv4 proxy).
- ICMP (ping) is not proxied — SOCKS5 does not support it.
- A few code paths (raw `ConnectEx` with overlapped synchronous completion, some overlapped UDP variants) are simplified and may not suit every application.

## License

MIT
