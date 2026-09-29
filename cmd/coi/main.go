package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/mensfeld/coi/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		var exitErr *cli.ExitCodeError
		if errors.As(err, &exitErr) {
			// An ExitCodeError carries its own code and (optional) user-facing
			// message; print it bare, and exit silently when there is none.
			if exitErr.Message != "" {
				fmt.Fprintln(os.Stderr, exitErr.Message)
			}
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(cli.ExitCodeFor(err))
	}
}
