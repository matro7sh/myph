package main

import (
	"github.com/cmepw/myph/cli"
)

func main() {
	var buildType string
	opts := cli.GetDefaultCLIOptions(buildType)
	parser := cli.GetParser(&opts)

	parser.ExecuteC()
}
