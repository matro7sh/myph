package cli

import (
	"crypto/rand"
)

// Get default value for Options struct
func GetDefaultCLIOptions() Options {
	opts := Options{
		ShellcodePath:  "msf.raw",
		Outfile:        "myph-out",
		OS:             "windows",
		arch:           "amd64",
		Target:         "",
        Encryption:     encKindAES,
        Key:            "",
	}

	return opts
}

// Generate a random list of bytes
func RandBytes(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}
