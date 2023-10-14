package internals

import (
	"syscall"
	"unsafe"
)

/*

   this structs are re-defined again in order to have access to
   private fields as well as the documented ones

*/

type PEB struct {
	InheritedAddressSpace    byte
	ReadImageFileExecOptions byte
	BeingDebugged            byte
	BitField                 byte
	Mutant                   uintptr
	ImageBaseAddress         uintptr
	Ldr                      *PEB_LDR_DATA
}

type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint8
	SsHandle                        uintptr
	InLoadOrderModuleList           LIST_ENTRY
	InMemoryOrderModuleList         LIST_ENTRY
	InInitializationOrderModuleList LIST_ENTRY
}

type LIST_ENTRY struct {
	Flink uintptr
	Blink uintptr
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks           LIST_ENTRY
	InMemoryOrderLinks         LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uint32
	FullDllName                UNICODE_STRING
	BaseDllName                UNICODE_STRING
	Flags                      uint32
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  LIST_ENTRY
	SectionPointer             uintptr
	CheckSum                   uint32
	TimeDateStamp              uint32
}

type TEB struct {
	Reserved1                    [195]uint8
	Peb                          *PEB
	Reserved2                    [12]uint8
	ClientId                     CLIENT_ID
	ActiveRpcInfo                uintptr
	ThreadLocalStorage           [64]uintptr
	Reserved3                    [45]uintptr
	ProcessEnvironmentBlock      *PEB
	Reserved4                    [103]uintptr
	LastErrorValue               uint32
	CountOfOwnedCriticalSections int32
	CsrClientThread              uintptr
	Win32ThreadInfo              *TIB
	Win32ClientInfo              [31]uintptr
	Reserved5                    [3]uintptr
	ExceptionCode                uint32
	Reserved6                    [41]uint8
	GdiRgn                       HANDLE
	GdiPen                       HANDLE
	GdiBrush                     HANDLE
	RealClientId                 CLIENT_ID
	GdiCachedProcessHandle       HANDLE
	GdiClientPID                 uint32
	GdiClientTID                 uint32
	GdiThreadLocalInfo           uintptr
	User32Reserved               [62]uint32
	UserReserved                 [5]uint32
	WOW32Reserved                [37]uintptr
	Reserved7                    int32
	PebReadOnly                  uintptr
	SharedInfo                   uintptr
	LocaleId                     uint32
	Reserved8                    [16]uint32
	ActCtxCurrent                uintptr
	DllBase                      [16]uintptr
	NumThids                     uint32
	Unknown1                     uint32
	Unknown2                     uintptr
	Unknown3                     uintptr
	TlsSlots                     [64]uintptr
}

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type TIB struct {
	ExceptionList   uintptr
	StackBase       uintptr
	StackLimit      uintptr
	SubSystemTib    uintptr
	UmsLink         uintptr
	ContextSwitches uint32
	Reserved1       [16]uint32
	Reserved2       uintptr
}

type HANDLE uintptr

var (
	ntdll                     = syscall.NewLazyDLL("ntdll.dll")
	ntQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
)

func NtCurrentTeb() *TEB {
	teb := &TEB{}
	ntQueryInformationProcess.Call(0, 0, uintptr(unsafe.Pointer(teb)), unsafe.Sizeof(*teb), 0)
	return teb
}

func LoadDLL(hash string) *syscall.DLL {
	// TODO
	return nil
}
