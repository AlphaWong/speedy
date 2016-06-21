package cmd

import (
	"fmt"
	"time"

	"github.com/nats-io/nats"
	"github.com/netlify/messaging"
	"github.com/spf13/cobra"
)

var reportSec int

// CountCmd will cause the client to listen forever
var CountCmd = cobra.Command{
	Use:   "count",
	Short: "count <subject> [group]",
	Run: func(cmd *cobra.Command, args []string) {
		cfgFile := configOrDie(cmd)
		subject, _ := zipArgs(cmd, args, []string{"subject"})["subject"]

		group := ""
		if len(args) == 2 {
			group = args[1]
		}

		listenAndCountForever(cfgFile, subject, group)
	},
}

func init() {
	CountCmd.Flags().IntVarP(&reportSec, "report", "r", 10, "how often to report the count")
}

func listenAndCountForever(cfgFile, subject, group string) {
	natsConfig := new(messaging.NatsConfig)
	err := loadFromFile(cfgFile, natsConfig)
	if err != nil {
		panic(err)
	}

	nc, err := messaging.ConnectToNats(natsConfig)
	if err != nil {
		panic(err)
	}

	msgChan := make(chan *nats.Msg)
	if group != "" {
		nc.ChanQueueSubscribe(subject, group, msgChan)
		fmt.Printf("Starting to listen to %s/%s forever\n", subject, group)
	} else {
		nc.ChanSubscribe(subject, msgChan)
		fmt.Printf("Starting to listen to %s forever\n", subject)
	}
	var msgCount int64
	since := time.Now().Format(time.RFC3339)
	go func() {
		for range time.Tick(time.Duration(reportSec) * time.Second) {
			now := time.Now().Format(time.RFC3339)
			fmt.Printf("%s: %d messages recieved since %s\r", now, msgCount, since)
		}
	}()

	for range msgChan {
		msgCount++
	}
}
