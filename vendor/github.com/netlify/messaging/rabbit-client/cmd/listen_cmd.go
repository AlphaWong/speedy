package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/netlify/messaging"
	"github.com/spf13/cobra"
)

// ListenCmd will read a file specified and send it to the subject/group specified
var ListenCmd = cobra.Command{
	Use:   "listen",
	Short: "listen [<exchange> <queue> || -b]",
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

		return listen(configFile, exDef, queueDef)
	},
}

func init() {
	ListenCmd.Flags().StringVarP(&bindingFile, "binding", "b", "", "A file to read and send")
	ListenCmd.Flags().StringVarP(&exchangeType, "exchange", "e", "direct", "the type of exchange")
	ListenCmd.Flags().StringVarP(&routingKey, "key", "k", "", "a routing key to use")
	ListenCmd.Flags().IntVarP(&delayMS, "delay", "d", 0, "how long (in MS) to pause between writes")
	ListenCmd.Flags().BoolVarP(&isJSON, "json", "j", false, "if the data is json")
}

func listen(cfgFile string, exDef *messaging.ExchangeDefinition, queueDef *messaging.QueueDefinition) error {
	ac, err := connect(cfgFile)
	if err != nil {
		return err
	}

	channel, queue, err := messaging.Bind(ac, exDef, queueDef)
	if err != nil {
		return err
	}

	incoming, err := messaging.Consume(channel, messaging.NewDeliveryDefinition(queue.Name))
	if err != nil {
		return err
	}

	fmt.Println("Starting to consume forever")
	fmt.Printf("Exchange: %+v\n", exDef)
	fmt.Printf("Queue: %+v\n", queueDef)
	for delivery := range incoming {
		data := delivery.Body
		if isJSON {
			parsed := new(map[string]interface{})
			err = json.Unmarshal(delivery.Body, parsed)
			if err != nil {
				fmt.Printf("Problem parsing data: %v\n", err)
			}
			// now pretty it up
			bs, err := json.MarshalIndent(parsed, "", "  ")
			if err != nil {
				fmt.Printf("Problem prettying data: %v\n", err)
			} else {
				data = bs
			}
		}
		fmt.Println(string(data))
	}

	return nil
}
