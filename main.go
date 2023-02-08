package main

import (
	"github.com/cmepw/myph/cli"
)

func main() {
	opts := cli.GetDefaultCLIOptions()
	parser := cli.GetParser(&opts)

	parser.ExecuteC()
}
