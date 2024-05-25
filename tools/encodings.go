package tools

import (
	b32 "encoding/base32"
	b64 "encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"time"
)

// / Enum type that defines which bytes encoding to use
// / in template source-code
type BytesEncodingType string

const (
	EncodingBase64 BytesEncodingType = "base64"
	EncodingBase32 BytesEncodingType = "base32"
	EncodingHex    BytesEncodingType = "hex"
)

// / Available encodings type
var Encodings = [3]string{"base64", "base32", "hex"}

// String is used both by fmt.Print and by Cobra in help text
func (e *BytesEncodingType) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *BytesEncodingType) Set(v string) error {
	switch v {
	case "base64", "base32", "hex":
		*e = BytesEncodingType(v)
		return nil
	default:
		return errors.New(`unknown encoding type`)
	}
}

// / Type is only used in help text
func (e *BytesEncodingType) Type() string {
	return "BytesEncodingType"
}

// / Select a random encoding type
func SelectRandomEncodingType() BytesEncodingType {
	rand.Seed(time.Now().Unix())
	n := rand.Int() % len(Encodings)

	return BytesEncodingType(Encodings[n])
}

// / Encode a series of bytes so that it can be interpolated into a template
func EncodeForInterpolation(method BytesEncodingType, toEncode []byte) string {

	switch method {

	case EncodingBase64:
		return fmt.Sprintf("\"%s\"", b64.StdEncoding.EncodeToString(toEncode))

	case EncodingBase32:
		return fmt.Sprintf("\"%s\"", b32.StdEncoding.EncodeToString(toEncode))

	case EncodingHex:
		return fmt.Sprintf("\"%s\"", hex.EncodeToString(toEncode))

	default:
		return ""
	}
}
