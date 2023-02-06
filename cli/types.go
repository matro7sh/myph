package cli

type Options struct {

    // Shellcode path
    ShellcodePath string

    // Outfile path
    Outfile string

    // AES shellcode encryption secret
    AesKey []byte
}
