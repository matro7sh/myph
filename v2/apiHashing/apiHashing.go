package apihashing

import (
	"github.com/cmepw/myph/internals"
	"github.com/cmepw/myph/v2/utils"
)

// APIHashingConfig is stored in the Compilation profile and manages all things related to API-Hashing
type APIHashingConfig struct {
	IsEnabled bool
	Technique ApiHashTechnique
}

type ApiHashTechnique string

const (
	DJB2   ApiHashTechnique = "DJB2"
	SHA1   ApiHashTechnique = "SHA1"
	SHA256 ApiHashTechnique = "SHA256"
	SHA512 ApiHashTechnique = "SHA512"
)

func (e *ApiHashTechnique) String() string {
	return string(*e)
}

func (e *ApiHashTechnique) Set(v string) error {
	err := utils.ValidateString(v, []string{"DJB2", "SHA1", "SHA256", "SHA512"})
	if err != nil {
		return err
	}
	*e = ApiHashTechnique(v)
	return nil
}

func (e *ApiHashTechnique) Type() string {
	return "API Hashing algorithm (DJB2, SHA1, SHA256, SHA512)"
}

func (a ApiHashTechnique) HashItem(item string) string {
	switch a {
	case DJB2:
		return internals.HashDJB2(item)
	case SHA1:
		return internals.HashSHA1(item)
	case SHA256:
		return internals.HashSHA256(item)
	case SHA512:
		return internals.HashSHA512(item)
	}
	return item
}
