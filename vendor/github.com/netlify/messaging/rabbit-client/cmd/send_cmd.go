package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/streadway/amqp"

	"github.com/netlify/messaging"
)

var sendFile string
var times int

// SendCmd will read a file specified and send it to the subject/group specified
var SendCmd = cobra.Command{
	Use:   "send",
	Short: "send [<exchange> <queue> || -b] [ data || -f ]",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := configOrDie(); err != nil {
			return err
		}

		var exDef *messaging.ExchangeDefinition
		var queueDef *messaging.QueueDefinition
		if bindingFile == "" {
			if len(args) < 2 {
				return errors.New("require an exchange and queue name")
			}

			exDef = messaging.NewExchangeDefinition(args[0], exchangeType)
			queueDef = messaging.NewQueueDefinition(args[1], routingKey)
		} else {
			def := new(bindDefinition)
			err := loadFromFile(bindingFile, def)
			if err != nil {
				return err
			}
			exDef = &def.Exchange
			queueDef = &def.Queue
		}

		var data []byte
		var err error
		if sendFile != "" {
			data, err = ioutil.ReadFile(sendFile)
			if err != nil {
				return err
			}
		} else {
			if bindingFile == "" {
				if len(args) < 3 {
					return errors.New("must provide some data to send")
				}
				data = []byte(strings.Join(args[2:], " "))
			} else {
				if len(args) == 0 {
					return errors.New("must provide some data to send")
				}
				data = []byte(strings.Join(args[:], " "))
			}
		}

		return send(configFile, exDef, queueDef, data)
	},
}

func init() {
	SendCmd.Flags().StringVarP(&sendFile, "file", "f", "", "A file to read and send")
	SendCmd.Flags().StringVarP(&bindingFile, "binding", "b", "", "A file to read and send")
	SendCmd.Flags().StringVarP(&exchangeType, "exchange", "e", "direct", "the type of exchange")
	SendCmd.Flags().StringVarP(&routingKey, "key", "k", "", "a routing key to use")
	SendCmd.Flags().IntVarP(&times, "times", "t", 1, "The number of times to send the message")
	SendCmd.Flags().IntVarP(&delayMS, "delay", "d", 0, "how long (in MS) to pause between writes")
	SendCmd.Flags().BoolVarP(&isJSON, "json", "j", false, "if the data is json")
}

func send(cfgFile string, exDef *messaging.ExchangeDefinition, queueDef *messaging.QueueDefinition, data []byte) error {
	ac, err := connect(cfgFile)
	if err != nil {
		return err
	}

	channel, _, err := messaging.Bind(ac, exDef, queueDef)
	if err != nil {
		return err
	}
	err = channel.Confirm(queueDef.NoWait)
	if err != nil {
		return err
	}

	contentType := "text/plain"
	if isJSON {
		contentType = "application/json"
	}

	for i := 0; i < times; i++ {
		fmt.Printf("%d/%d: Sending %d bytes of data to %s/%s/%s\n", i+1, times, len(data), exDef.Name, exDef.Type, queueDef.Name)
		err = channel.Publish(
			exDef.Name,
			routingKey,
			true,  // manditory
			false, // immediate
			amqp.Publishing{
				Headers:         amqp.Table{},
				ContentType:     contentType,
				ContentEncoding: "",
				Body:            data,
				DeliveryMode:    amqp.Transient,
				Priority:        0,
			},
		)
		if err != nil {
			return err
		}

		if delayMS > 0 {
			fmt.Printf("sleeping for %d ms....", delayMS)
			time.Sleep(time.Duration(delayMS) * time.Millisecond)
			fmt.Println("awake")
		}
	}

	fmt.Println("completed")
	return nil
}
