package tools

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/blowfish"
)

func GetBlowfishTemplate() string {
	return fmt.Sprintf(`
package main

import (
    "golang.org/x/crypto/blowfish"

    "crypto/cipher"
)

func Decrypt(toDecrypt []byte, key []byte) ([]byte, error) {
    dcipher, err := blowfish.NewCipher(key)
    if err != nil {
        return []byte{}, err
    }

    div := toDecrypt[:blowfish.BlockSize]
    decrypted := toDecrypt[blowfish.BlockSize:]
    dcbc := cipher.NewCBCDecrypter(dcipher, div)
    dcbc.CryptBlocks(decrypted, decrypted)

    return decrypted, nil
}
    `)
}

func GetAESTemplate() string {
	return fmt.Sprintf(`
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "errors"
)

func Decrypt(encrypted []byte, key []byte) ([]byte, error) {
    c, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(c)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(encrypted) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}
    `)
}

func GetXORTemplate() string {
	return fmt.Sprintf(`
package main

func Decrypt(toDecrypt []byte, key []byte) ([]byte, error) {
    encrypted := make([]byte, len(toDecrypt))
    keyLen := len(key)

    for i, b := range toDecrypt {
        encrypted[i] = b ^ key[i %% keyLen]
    }
    return encrypted, nil
}
    `)
}

func EncryptBlowfish(toCrypt []byte, key []byte) ([]byte, error) {

	/*
	   let's add the required padding :)~
	   source: https://stackoverflow.com/a/46747195
	*/

	modulus := len(toCrypt) % blowfish.BlockSize
	if modulus != 0 {
		padlen := blowfish.BlockSize - modulus
		for i := 0; i < padlen; i++ {
			toCrypt = append(toCrypt, 0)
		}
	}

	ecipher, err := blowfish.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	ciphertext := make([]byte, blowfish.BlockSize+len(toCrypt))
	eiv := ciphertext[:blowfish.BlockSize]
	ecbc := cipher.NewCBCEncrypter(ecipher, eiv)
	ecbc.CryptBlocks(ciphertext[blowfish.BlockSize:], toCrypt)

	return ciphertext, nil
}

func DecryptBlowfish(toDecrypt []byte, key []byte) ([]byte, error) {
	dcipher, err := blowfish.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	div := toDecrypt[:blowfish.BlockSize]
	decrypted := toDecrypt[blowfish.BlockSize:]
	dcbc := cipher.NewCBCDecrypter(dcipher, div)
	dcbc.CryptBlocks(decrypted, decrypted)

	return decrypted, nil
}

func EncryptXOR(toEncrypt []byte, key []byte) ([]byte, error) {
	encrypted := make([]byte, len(toEncrypt))
	keyLen := len(key)

	for i, b := range toEncrypt {
		encrypted[i] = b ^ key[i%keyLen]
	}
	return encrypted, nil
}

func DecryptXOR(toDecrypt []byte, key []byte) ([]byte, error) {
	encrypted := make([]byte, len(toDecrypt))
	keyLen := len(key)

	for i, b := range toDecrypt {
		encrypted[i] = b ^ key[i%keyLen]
	}
	return encrypted, nil
}

func EncryptAES(toEncrypt []byte, key []byte) ([]byte, error) {
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

	return gcm.Seal(nonce, nonce, toEncrypt, nil), nil
}

func DecryptAES(encrypted []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
