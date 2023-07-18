package cli

import "errors"

/// encryption kind (used for CLI)
type encKind string

const (
    EncKindAES encKind = "AES"
    EncKindXOR encKind = "XOR"
    EncKindBLF encKind = "Blowfish"
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
        return errors.New(`must be one of "AES" or "XOR"`)
    }
}

// Type is only used in help text
func (e *encKind) Type() string {
    return "encKind"
}


type Options struct {

    // Shellcode encryption method
    Encryption encKind

    // Encryption key (if needed)
    Key string

	// Shellcode path
	ShellcodePath string

	// Outdir path
	Outdir string

	// os compilation target
	OS string

	// arch compilation target
	arch string

	// target process name to inject
	Target string
}
