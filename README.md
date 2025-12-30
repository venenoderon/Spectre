# Introducing gigi – A Stealthy Go Loader Template for Windows (amd64)

`gigi` is a Go-based tool, built for red teamers and pentesters who need a lightweight, shellcode-oriented loader with modern evasive techniques. It mixes Go with minimal assembly to avoid CRT bloat, bypass import tables, and stay resilient against userland hooks.

## Why gigi
- **Import-less discovery:** PEB walking from Go assembly (`GS:[0x60]`) to enumerate modules without WinAPI/IAT.
- **Hashed resolution + forwarders:** FNV-1a for ANSI/WCHAR, forwarder-aware export parsing (e.g., `KERNEL32.Sleep` → `NTDLL.Sleep`), and a tiny cache to avoid repeated loader walks.
- **Clean syscalls:** Maps `ntdll.dll` as a datafile to read unhooked stubs, extracts syscall IDs, and invokes a raw syscall stub (3 args) for hook-resistant calls (demo: `NtDelayExecution`).
- **String obfuscation:** Lightweight XOR wrapper that decrypts on the stack, null-terminated for API calls.
- **ETW suppression (optional):** Helper to NOP `EtwEventWrite` to reduce telemetry noise.
- **Shellcode-friendly builds:** `-trimpath` and `-ldflags="-s -w -H=windowsgui -buildid="` for compact binaries; PowerShell script to dump `.text` as raw shellcode.

## Demo Flow
- Resolves `MessageBoxA` (strings obfuscated), SRW lock forwarders (into ntdll), performs a direct-syscall sleep, and exits via `ExitProcess`.
- No import table lookups for the critical pieces; resolution happens via hashed exports and PEB walking.

## Build
```powershell
cd AdvancedZetsuGo
go env -w GOOS=windows GOARCH=amd64
go build -trimpath -ldflags="-s -w -H=windowsgui -buildid=" -o bin/payload.exe ./cmd/payload
