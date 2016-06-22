package main

import (
	"os"

	"github.com/netlify/messaging/rabbit-client/cmd"
)

func main() {
	cmd.RootCmd.AddCommand(
		&cmd.ListenCmd,
		&cmd.SendCmd,
	)

	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
