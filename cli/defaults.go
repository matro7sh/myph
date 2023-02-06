package cli

import (
	"crypto/rand"
)

// Get default value for Options struct
func GetDefaultCLIOptions() Options {
    opts := Options{
        ShellcodePath: "",
        AesKey: RandBytes(32),
        Outfile: "myph-out",
    }

    return opts
}

func RandBytes(length int) []byte {
    b := make([]byte, length)
    rand.Read(b)
    return b
}
