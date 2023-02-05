package loader;


type Shellcode struct {
    // payload in bytes
    Payload []byte

    // output filename
    Filename string

    // symbol name in program memory
    SymbolName string

    // AES key used for encryption & decrpytion
    AesKey []byte
}
