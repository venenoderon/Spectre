//go:build windows && amd64

package main

import (
	"syscall"
	"unsafe"

	"gigi/internal/obfuscate"
	"gigi/internal/resolver"
)

type SRWLOCK struct {
	ptr uintptr
}

const (
	MB_OK              = 0x00000000 // Botón OK
	MB_ICONINFORMATION = 0x00000040 // Ícono informativo
)

func main() {
	kernel := resolver.FindModule(resolver.HashW("kernel32.dll"), "")
	user32 := resolver.FindModule(resolver.HashW("user32.dll"), "user32.dll")
	ntdll := resolver.FindModule(resolver.HashW("ntdll.dll"), "ntdll.dll")

	if kernel == 0 {
		return
	}

	pExitProcess := resolver.GetProc[uintptr](kernel, resolver.HashC("ExitProcess"))
	pMessageBoxA := resolver.GetProc[uintptr](user32, resolver.HashC("MessageBoxA"))
	pAcquire := resolver.GetProc[uintptr](kernel, resolver.HashC("AcquireSRWLockExclusive")) // reenviado a ntdll
	pRelease := resolver.GetProc[uintptr](kernel, resolver.HashC("ReleaseSRWLockExclusive")) // reenviado a ntdll
	pNtDelay := resolver.GetProc[uintptr](ntdll, resolver.HashC("NtDelayExecution"))

	var lock SRWLOCK
	locked := false

	if pAcquire != 0 && pRelease != 0 {
		syscall.SyscallN(pAcquire, uintptr(unsafe.Pointer(&lock)))
		locked = true
	}

	if pMessageBoxA != 0 {
		body := obfuscate.XORStr("Payload de Go enfocado a shellcode ejecutándose.")
		title := obfuscate.XORStr("gigi")

		syscall.SyscallN(pMessageBoxA,
			0,
			uintptr(unsafe.Pointer(&body[0])),
			uintptr(unsafe.Pointer(&title[0])),
			uintptr(MB_OK|MB_ICONINFORMATION),
		)
	}

	if locked {
		syscall.SyscallN(pRelease, uintptr(unsafe.Pointer(&lock)))
	}

	// Demostración de “sleep” resistente a hooks usando syscall directo (sin IAT).
	if pNtDelay != 0 {
		if sysid, ok := resolver.ResolveSyscallID("NtDelayExecution", pNtDelay); ok {
			// Unidades de 100 ns negativas: -1s para simular trabajo sin UI.
			interval := int64(-1_0000_0000)
			resolver.NtDelayExecution(sysid, 0, &interval)
		}
	}

	if pExitProcess != 0 {
		syscall.SyscallN(pExitProcess, 0)
	}
}
