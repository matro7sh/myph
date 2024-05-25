package cli

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
)

func GetDependencies(opts *Options, tempDirPath string) {

	if opts.CompileConfig.APIHashingConfig.IsEnabled {
		fmt.Println("[!] Downloading necessary dependencies for API hashing")

		execGoGetCmd := exec.Command("go", "get", "github.com/Binject/debug/pe")
		execGoGetCmd.Dir = tempDirPath
		_, err := execGoGetCmd.Output()
		exitIfError(err)

		execGoGetCmd = exec.Command("go", "get", "github.com/cmepw/myph/internals")
		execGoGetCmd.Dir = tempDirPath
		_, err = execGoGetCmd.Output()
		exitIfError(err)
	}
}

func GetTempDirPath() string {
	if runtime.GOOS == "windows" {
		userCtx, err := user.Current()
		if err != nil {
			fmt.Println("Error getting current user:", err)
			return "myph-dist"
		}

		tempDir := filepath.Join(userCtx.HomeDir, "AppData", "Local", "Temp", "myph")
		return tempDir
	} else {
		tempDir := filepath.Join("/tmp", "myph")
		return tempDir
	}
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

func exitIfError(err error) {
	if err != nil {
		fmt.Println("[!] Unexpected error:", err)
		os.Exit(1)
	}
}

func dirExists(dir string) (bool, error) {
	_, err := os.Stat(dir)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func CreateTmpProjectRoot(path string) error {

	fmt.Printf("[+] Initializing temporary build directory: %s\n", path)

	/*
	   create a directory with the path name
	   defined by the options
	*/

	exists, err := dirExists(path)
	if err != nil {
		return err
	}

	if exists {
		fmt.Printf("[!] %s already exists...Removing\n", path)
		err := os.RemoveAll(path)
		if err != nil {
			return err
		}
	}

	err = os.MkdirAll(path, 0777)
	if err != nil {
		return err
	}

	var goMod = []byte(`
module evil

go 1.19

    `)

	gomodPath := fmt.Sprintf("%s/go.mod", path)
	fo, err := os.Create(gomodPath)
	_, err = fo.Write(goMod)
	if err != nil {
		return err
	}

	maingoPath := fmt.Sprintf("%s/main.go", path)
	_, err = os.Create(maingoPath)
	if err != nil {
		return err
	}

	execgoPath := fmt.Sprintf("%s/exec.go", path)
	_, err = os.Create(execgoPath)
	if err != nil {
		return err
	}

	encryptgoPath := fmt.Sprintf("%s/encrypt.go", path)
	_, err = os.Create(encryptgoPath)
	if err != nil {
		return err
	}

	return nil
}
