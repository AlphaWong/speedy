package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/streadway/amqp"

	"github.com/netlify/messaging"
)

var configFile string

var bindingFile string
var routingKey string
var exchangeType string
var delayMS int
var isJSON bool

// RootCmd is where all the magic is
var RootCmd = cobra.Command{
	Use: "util",
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file to use")
}

type bindDefinition struct {
	Exchange messaging.ExchangeDefinition `json:"exchange_def"`
	Queue    messaging.QueueDefinition    `json:"queue_def"`
}

func loadFromFile(configFile string, configStruct interface{}) error {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, configStruct)
	if err != nil {
		return err
	}

	return nil
}

func connect(configFile string) (*amqp.Connection, error) {
	rabbitConfig := new(messaging.RabbitConfig)
	err := loadFromFile(configFile, rabbitConfig)
	if err != nil {
		return nil, err
	}

	ac, err := messaging.ConnectToRabbit(rabbitConfig)
	if err != nil {
		return nil, err
	}
	return ac, nil
}

func configOrDie() error {
	if configFile == "" {
		return errors.New("Require a config file")
	}

	return nil
}

func zipArgs(c *cobra.Command, args []string, expectedArgs []string) map[string]string {
	if len(expectedArgs) > len(args) {
		fmt.Println("Not enough args provided. Expected: " + strings.Join(expectedArgs, " "))
		c.Help()
		os.Exit(1)
	}
	res := make(map[string]string)
	for i, arg := range expectedArgs {
		res[arg] = args[i]
	}

	return res
}
