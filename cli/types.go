package cli

import "errors"

// encryption kind (used for CLI)
type encKind string

// shellcode-loading technique kind (used for CLI)
type technique string

const (
	EncKindAES encKind = "AES"
	EncKindXOR encKind = "XOR"
	EncKindBLF encKind = "Blowfish"

	CRT          technique = "CRT"
	CreateThread technique = "CreateThread"
)

// String is used both by fmt.Print and by Cobra in help text
func (e *encKind) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *encKind) Set(v string) error {
	switch v {
	case "AES", "XOR":
		*e = encKind(v)
		return nil
	default:
		return errors.New("must be one of \"AES\" or \"XOR\"\n\n")
	}
}

// Type is only used in help text
func (e *encKind) Type() string {
	return "encKind"
}

// String is used both by fmt.Print and by Cobra in help text
func (e *technique) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *technique) Set(v string) error {
	switch v {
	case "CreateThread", "CRT":
		*e = technique(v)
		return nil
	default:
		return errors.New("must be one of \"CRT\" or \"CreateThread\"\n\n")
	}
}

// Type is only used in help text
func (e *technique) Type() string {
	return "technique"
}

type Options struct {

	// Shellcode encryption method
	Encryption encKind

	// Encryption key (if needed)
	Key string

	// Shellcode path
	ShellcodePath string

	// OutName path
	OutName string

	// os compilation target
	OS string

	// Arch compilation target
	Arch string

	// target process name to inject
	Target string

	// Shellcode loading method
	Technique string
}
