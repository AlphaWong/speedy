package cmd

import (
	"github.com/Sirupsen/logrus"
	"github.com/netlify/speedy/timing"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var singleCmd = &cobra.Command{
	Use:   "single",
	Short: "single <url>",
	Run:   runSingle,
}

func runSingle(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		logrus.Fatal("Must provide a URL to test")
	}

	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		logrus.WithError(err).Fatal("Failed to bind to pflags")
	}

	if viper.GetBool("verbose") {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	timing.ProcessSingle(args[0])
}
