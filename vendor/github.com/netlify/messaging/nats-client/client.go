package main

import (
	"os"

	"github.com/netlify/messaging/nats-client/cmd"
)

func main() {
	cmd.RootCmd.AddCommand(
		&cmd.ListenCmd,
		&cmd.SendCmd,
		&cmd.LogCmd,
		&cmd.CountCmd,
	)

	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
