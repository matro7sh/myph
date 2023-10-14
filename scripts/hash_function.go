package main

import (
	"fmt"
	"os"

	hash "github.com/cmepw/myph/internals"
	"github.com/spf13/cobra"
)

func main() {

	var rootCmd = &cobra.Command{
		Use:   "hash",
		Short: "hash-command",
		Long:  `Computes the hash for a given function or library name`,
		Run: func(cmd *cobra.Command, args []string) {

			if len(args) != 1 {
				fmt.Println("hash-command only accepts one argument")
				os.Exit(1)
			}

			toHash := args[0]

			fmt.Printf("\t{\n\t\tName: \"%s\",\n", toHash)
			fmt.Printf("\t\tSha1: \"%s\",\n", hash.HashSHA1(toHash))
			fmt.Printf("\t\tSha256: \"%s\",\n", hash.HashSHA256(toHash))
			fmt.Printf("\t\tSha512: \"%s\",\n", hash.HashSHA512(toHash))
			fmt.Printf("\t\tDjb2: \"%s\",\n", hash.HashDJB2(toHash))

			fmt.Printf("\t},\n")

		},
	}

	err := rootCmd.Execute()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
