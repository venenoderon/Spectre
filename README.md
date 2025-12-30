# Spectre

Spectre (Golang) is a shellcode template with heavier emphasis on stealth techniques: PEB-only module discovery via Go assembly, hashed export resolution with forwarder support, XOR-obfuscated literals, and a sample payload that never calls Win32 import tables directly. Targets Windows/amd64.

## Why this is more advanced
- **Import-less PEB walker:** `getPEB` is Go assembly reading `GS:[0x60]`, no WinAPI to enumerate modules.
- **Hashed resolution + forwarders:** FNV-1a hashing for ANSI/WCHAR names, export parser handles forwarders (e.g., `KERNEL32.Sleep` -> `NTDLL.Sleep`), plus a tiny cache.
- **Self-bootstrapping:** Missing modules are pulled in with hashed `LoadLibraryA`.
- **Direct syscalls:** Syscall ID extraction from live or cleanly-mapped ntdll stubs and a raw `syscall` stub for hook-resistant calls.
- **Clean ntdll mapping:** Loads `ntdll.dll` as a datafile to read unhooked syscall stubs before executing them.
- **Telemetry reduction:** Optional ETW patch to NOP `EtwEventWrite`.
- **Literal obfuscation:** XOR wrapper decrypts on-stack per call site (null-terminated for API calls).
- **Shellcode-friendly build flags:** `-trimpath -ldflags="-s -w -H=windowsgui -buildid="` guidance and a `.text` extractor script.

## Build
```powershell
cd Spectre
go env -w GOOS=windows GOARCH=amd64
go build -trimpath -ldflags="-s -w -H=windowsgui -buildid=" -o bin/payload.exe ./cmd/payload
```

## Extract `.text` as raw shellcode
```powershell
powershell -File scripts/extract-text.ps1 -Binary .\bin\payload.exe -Output .\bin\payload.bin
```
Uses `llvm-objcopy`/`objcopy` if available in PATH.

## Files
- `cmd/payload/main_windows.go` — demo payload resolving `MessageBoxA`, SRW forwarders, doing a direct-syscall `NtDelayExecution`, and exiting.
- `internal/resolver/peb_amd64.s` — Go assembly to fetch the PEB without WinAPI.
- `internal/resolver/resolver_windows.go` — hashed module/API resolver, forwarder handling, module cache, syscall ID extraction, ETW patch helper.
- `internal/resolver/cleanntdll_windows.go` — clean ntdll datafile mapping and syscall ID resolution from unhooked stubs.
- `internal/resolver/syscall_amd64.s` — raw Windows syscall stub for 3-arg syscalls.
- `internal/obfuscate/xor.go` — XOR literal helper with per-callsite keys.
- `scripts/extract-text.ps1` — `.text` dump helper.

## Notes
- This is still a Go binary (runtime present). For true shellcode-size payloads you’d typically transcode generated machine code or emit a minimal PE manually. The resolver logic here is ready to be transplanted into a thinner runtime if needed.
- All code is Windows/amd64 only (`//go:build windows && amd64`).
