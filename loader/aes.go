package loader

import (
	"crypto/aes"
	"fmt"

	"crypto/cipher"
	"crypto/rand"
	"io"
)

func ToString(payload []byte) string {
	return fmt.Sprint([]byte(payload))
}

func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}
