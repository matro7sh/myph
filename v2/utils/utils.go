package utils

import (
	"errors"
	"strings"
)

func ValidateString(v string, validStrings []string) error {
	for _, s := range validStrings {
		if v == s {
			return nil
		}
	}
	return errors.New("must be one of " + strings.Join(validStrings, "\", \""))
}
