package main

import (
	"os"

	"github.com/filipi86/drogonsec/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
