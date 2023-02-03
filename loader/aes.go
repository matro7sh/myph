package loader;


import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

func EncryptPayload(key []byte, payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddingLen := aes.BlockSize - (len(payload) % aes.BlockSize)
	paddingText := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	textWithPadding := append(payload, paddingText...)

	ciphertext := make([]byte, aes.BlockSize+len(textWithPadding))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfbEncrypter := cipher.NewCFBEncrypter(block, iv)
	cfbEncrypter.XORKeyStream(ciphertext[aes.BlockSize:], textWithPadding)

	return ciphertext, nil
}

func DecryptPayload(key []byte, payload []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if (len(payload) % aes.BlockSize) != 0 {
		return nil, errors.New("payload length should be % of AES blocksize")
	}

	iv := payload[:aes.BlockSize]

	decodedCipherMsg := payload[aes.BlockSize:]
	cfbDecrypter := cipher.NewCFBDecrypter(block, iv)
	cfbDecrypter.XORKeyStream(decodedCipherMsg, decodedCipherMsg)

	length := len(decodedCipherMsg)
	paddingLen := int(decodedCipherMsg[length-1])
	result := decodedCipherMsg[:(length - paddingLen)]
	return result, nil
}
