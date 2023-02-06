package loader

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"os"
)

func ReadFile(filepath string) ([]byte, error) {

    buf := bytes.NewBuffer(nil)
    f, err := os.Open(filepath); if err != nil {
        return []byte{}, err
    }

    io.Copy(buf, f)
    f.Close()

    return buf.Bytes(), nil
}

func WriteToTempfile(payload string) error {
     // create file
    f, err := os.Create("tmp.go")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    buffer := bufio.NewWriter(f)
    _, err = buffer.WriteString(payload + "\n"); if err != nil {
        log.Fatal(err)
    }

    // flush buffered data to the file
    if err := buffer.Flush(); err != nil {
        log.Fatal(err)
    }
    return nil
}
