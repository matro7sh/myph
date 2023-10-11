package cli

import (
	"crypto/rand"
)

// Get default value for Options struct
func GetDefaultCLIOptions() Options {
	opts := Options{
		ShellcodePath:   "msf.raw",
		OutName:         "payload.exe",
		OS:              "windows",
		Arch:            "amd64",
		Target:          "cmd.exe",
		Encryption:      EncKindAES,
		Key:             "",
		Technique:       "CRT",
		SleepTime:       0,
		PEFilePath:      "payload.exe",
		VersionFilePath: "goversion.json",
		BuildType:       "exe",
	}

	return opts
}

// Generate a random list of bytes
func RandBytes(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}
