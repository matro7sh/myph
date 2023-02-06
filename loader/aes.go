package loader

import (
	"crypto/aes"
	"fmt"
	"os"
)

func Encrypt(key []byte, plaintext []byte) []byte {
    c, err := aes.NewCipher(key); if err != nil {
        fmt.Printf("[!] cipher gen: %s\n", err.Error())
        os.Exit(1)
    }

    out := make([]byte, len(plaintext))
    c.Encrypt(out, plaintext)
    return out
}
