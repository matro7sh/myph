package cli

import (
	"fmt"
	"os"

	"github.com/cmepw/myph/loader"
	"github.com/spf13/cobra"
)


func GetParser(opts *Options) *cobra.Command {
	version := "2.0.0"
	var cmd = &cobra.Command{
		Use:                "myph",
		Version:            version,
		DisableSuggestions: true,
		Short:              "minimal golang loader",
		Long:               `In loving memory of Wassyl Iaroslavovytch Slipak (1974 - 2016)`,
		Run: func(cmd *cobra.Command, args []string) {

			if opts.ShellcodePath == "" {
				fmt.Println("[!] Please specify your shellcode's path with --shellcode")
				os.Exit(1)
			}

            err := loader.CreateTmpProjectRoot(opts.Outfile)
            if err != nil {
                fmt.Printf("[!] Error generating project root: %s", err)
                os.Exit(1)
            }

            shellcode, err := loader.ReadFile(opts.ShellcodePath)
            if err != nil {
                fmt.Printf("[!] Error reading shellcode file: %s", err)
                os.Exit(1)
            }

            encType := loader.SelectRandomEncodingType()
            shellcodeAsString := loader.EncodeForInterpolation(encType, shellcode)

            fmt.Println(shellcodeAsString)

			os.Setenv("GOOS", opts.OS)
			os.Setenv("GOARCH", opts.arch)
        },


    }

	defaults := GetDefaultCLIOptions()

	cmd.PersistentFlags().StringVarP(&opts.Outfile, "outfile", "f", defaults.Outfile, "output filepath")
	cmd.PersistentFlags().StringVarP(&opts.ShellcodePath, "shellcode", "s", defaults.ShellcodePath, "shellcode path")

	cmd.PersistentFlags().StringVarP(&opts.arch, "arch", "r", defaults.arch, "architecture compilation target")
	cmd.PersistentFlags().StringVarP(&opts.OS, "os", "o", defaults.OS, "OS compilation target")

    cmd.PersistentFlags().VarP(&opts.Encryption, "encryption", "e", "encryption method. (allowed: AES, RSA, XOR, Blowfish)")
    cmd.PersistentFlags().StringVarP(&opts.Key, "key", "k", "", "encryption key, auto-generated if empty. (if used by --encryption-method)")

	return cmd
}
