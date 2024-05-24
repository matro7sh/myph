package cli

import (
	"crypto/rand"
	"fmt"
	"os/user"
	"path/filepath"
	"runtime"
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
		WithDebug:       false,
		BuildType:       "exe",
		Persistence:     "",
		UseAPIHashing:   false,
		APIHashingType:  "DJB2",
	}

	return opts
}

// RandBytes generates a random list of bytes
func RandBytes(length int) []byte {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil
	}
	return b
}

func GetTempPath() string {
	if runtime.GOOS == "windows" {
		userCtx, err := user.Current()
		if err != nil {
			fmt.Println("Error getting current user:", err)
			return "nouser\\Temp\\myph"
		}

		tempDir := filepath.Join(userCtx.HomeDir, "AppData", "Local", "Temp", "myph")
		return tempDir
	}

	return "/tmp/myph"
}
