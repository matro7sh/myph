package cli

import (
	"crypto/rand"
)

// Get default value for Options struct
func GetDefaultCLIOptions() Options {
    opts := Options{
        ShellcodePath: "",
        AesKey: RandBytes(32),
        Outfile: "myph-out.exe",
        OS: "windows",
        arch: "amd64",
    }

    return opts
}

// Generate a random list of bytes
func RandBytes(length int) []byte {
    b := make([]byte, length)
    rand.Read(b)
    return b
}
