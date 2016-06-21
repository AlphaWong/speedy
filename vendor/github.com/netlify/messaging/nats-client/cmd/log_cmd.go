package cmd

import (
	"fmt"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netlify/messaging"
)

// LogCmd will cause the client to log the message forever
var LogCmd = cobra.Command{
	Use: "log",
	Run: func(cmd *cobra.Command, args []string) {
		cfgFile := configOrDie(cmd)
		argMap := zipArgs(cmd, args, []string{"subject", "message"})
		subject, _ := argMap["subject"]
		msg, _ := argMap["message"]
		logForever(cfgFile, subject, msg)
	},
}

func init() {
	LogCmd.Flags().StringP("subject", "s", "", "The subject to send the message to")
}

func logForever(cfgFile, subject, msg string) {
	natsConfig := new(messaging.NatsConfig)
	err := loadFromFile(cfgFile, natsConfig)
	if err != nil {
		panic(err)
	}

	nc, err := messaging.ConnectToNats(natsConfig)
	if err != nil {
		panic(err)
	}

	hook, err := messaging.NewNatsHook(nc, subject)
	if err != nil {
		panic(err)
	}

	logrus.AddHook(hook)

	fmt.Printf("Starting to log '%s' to %s forever\n", msg, subject)
	count := 0
	for {
		logrus.Infof("%d: %s", count, msg)
		count++
		time.Sleep(time.Second)
	}
}
