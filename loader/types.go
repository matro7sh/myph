package loader

type Shellcode struct {
	// payload in bytes
	Payload []byte

	// output filename
	Filename string

	// AES key used for encryption & decrpytion
	AesKey []byte

	// target process name to inject
	Target string
}
