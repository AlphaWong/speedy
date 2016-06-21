package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats"
	"github.com/spf13/cobra"

	"github.com/netlify/messaging"
)

var delayListenMs int
var parseJSON = false

// ListenCmd will cause the client to listen forever
var ListenCmd = cobra.Command{
	Use:   "listen",
	Short: "listen <subject> [group]",
	Run: func(cmd *cobra.Command, args []string) {
		cfgFile := configOrDie(cmd)
		subject, _ := zipArgs(cmd, args, []string{"subject"})["subject"]

		group := ""
		if len(args) == 2 {
			group = args[1]
		}

		listenForever(cfgFile, subject, group)
	},
}

func init() {
	ListenCmd.Flags().IntVarP(&delayListenMs, "delay", "d", 0, "how long (in MS) to pause between reads")
	ListenCmd.Flags().BoolVarP(&parseJSON, "json", "j", false, "if the incoming data is json")
}

func listenForever(cfgFile, subject, group string) {
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

	for msg := range msgChan {
		if parseJSON {
			uglyForm := make(map[string]interface{})
			err := json.Unmarshal(msg.Data, &uglyForm)
			if err != nil {
				panic(err)
			}

			prettyForm, err := json.MarshalIndent(uglyForm, "", "  ")
			if err != nil {
				panic(err)
			}
			fmt.Println(string(prettyForm))
		} else {
			fmt.Println(string(msg.Data))
		}

		if delayListenMs > 0 {
			fmt.Printf("sleeping for %d ms....", delayListenMs)
			time.Sleep(time.Duration(delayListenMs) * time.Millisecond)
			fmt.Println("awake")
		}
	}
}
