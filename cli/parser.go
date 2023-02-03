package cli

import (
	"github.com/spf13/cobra"
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

            println("pee is stored in the balls")
        },

    }

    defaults := GetDefaultCLIOptions()

    cmd.PersistentFlags().StringVarP(&opts.Outfile, "outfile", "o", defaults.Outfile, "output filepath")
    cmd.PersistentFlags().StringVarP(&opts.ShellcodePath, "shellcode", "s", defaults.ShellcodePath, "shellcode path")

    return cmd
}
