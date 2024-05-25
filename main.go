package main

import (
	"github.com/cmepw/myph/v2/cli"
)

func main() {
	opts := cli.DefaultOptions()
	parser := cli.GetParser(&opts)

	_, err := parser.ExecuteC()
	if err != nil {
		return
	}
}
