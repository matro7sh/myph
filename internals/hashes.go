package internals

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

/*
   holds the different hashing algorithms available for this loader
*/

func HashSHA1(toHash string) string {
	h := sha1.New()
	h.Write([]byte(toHash))
	bs := h.Sum(nil)

	return fmt.Sprintf("%x", bs)
}

func HashSHA256(toHash string) string {
	h := sha256.New()
	h.Write([]byte(toHash))
	bs := h.Sum(nil)

	return fmt.Sprintf("%x", bs)
}

func HashSHA512(toHash string) string {
	h := sha512.New()
	h.Write([]byte(toHash))
	bs := h.Sum(nil)

	return fmt.Sprintf("%x", bs)
}

func HashDJB2(input string) string {
	hash := uint64(5381)

	for _, b := range input {
		hash += uint64(b) + hash + hash<<5
	}

	return fmt.Sprintf("%x", hash)
}
