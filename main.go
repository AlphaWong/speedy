package main

import (
	"github.com/sirupsen/logrus"
	"github.com/netlify/speedy/cmd"
)

func main() {
	if err := cmd.RootCmd().Execute(); err != nil {
		logrus.WithError(err).Fatal("Failed to run root cmd")
	}
}
