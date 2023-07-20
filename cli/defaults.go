package cli

import (
	"crypto/rand"
)

// Get default value for Options struct
func GetDefaultCLIOptions() Options {
	opts := Options{
		ShellcodePath: "msf.raw",
		Outdir:        "myph-out",
		OS:            "windows",
		arch:          "amd64",
		Target:        "cmd.exe",
		Encryption:    EncKindAES,
		Key:           "",
	}

	return opts
}

// Generate a random list of bytes
func RandBytes(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}
